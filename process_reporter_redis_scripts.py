"""Lua scripts used by the Redis process reporter write model."""

INITIALIZE_RUN_LUA = r"""
if redis.call('HEXISTS', KEYS[3], 'initialized_at') == 1 then
    return {0, redis.call('HGET', KEYS[3], 'last_event_id') or ''}
end

local run_id = ARGV[1]
local created_at = ARGV[2]
local score = tonumber(ARGV[3])
local graph_json = ARGV[4]
local tasks = cjson.decode(ARGV[5])
local metadata = cjson.decode(ARGV[6])
local total = tonumber(ARGV[7])
local maxlen = tonumber(ARGV[8])
local status = redis.call('HGET', KEYS[3], 'status')
if not status or status == 'queued' then
    status = 'starting'
end

redis.call('ZADD', KEYS[1], 'NX', score, run_id)
redis.call('SET', KEYS[4], graph_json, 'NX')
redis.call(
    'HSET', KEYS[3],
    'status', status,
    'created_at', redis.call('HGET', KEYS[3], 'created_at') or created_at,
    'initialized_at', created_at,
    'updated_at', created_at,
    'total', total,
    'pending', total,
    'running', 0,
    'succeeded', 0,
    'failed', 0,
    'skipped', 0,
    'aborted', 0,
    'run_revision', 0
)
for key, value in pairs(metadata) do
    if value ~= cjson.null then
        redis.call('HSET', KEYS[3], key, tostring(value))
    end
end
for _, task in ipairs(tasks) do
    redis.call('HSETNX', KEYS[5], task.id, 'pending')
    redis.call('HSETNX', KEYS[6], task.id, cjson.encode(task.data))
end

local event_id = redis.call(
    'XADD', KEYS[7], 'MAXLEN', '~', maxlen, '*',
    'type', 'run.initialized',
    'run_id', run_id,
    'status', status,
    'occurred_at', created_at,
    'revision', '0',
    'data', cjson.encode({run_id=run_id, status=status, total=total})
)
redis.call('HSET', KEYS[3], 'last_event_id', event_id)
return {1, event_id}
"""


TASK_TRANSITION_LUA = r"""
local task_id = ARGV[1]
local revision = tonumber(ARGV[2])
local new_status = ARGV[3]
local old_status = redis.call('HGET', KEYS[1], task_id) or 'pending'
local old_json = redis.call('HGET', KEYS[2], task_id)
local old_revision = -1
if old_json then
    local decoded = cjson.decode(old_json)
    old_revision = tonumber(decoded.revision) or -1
end
if revision <= old_revision then
    return {0, 'stale', old_revision}
end

local allowed = {
    pending = {running=true, skipped=true, aborted=true},
    running = {succeeded=true, failed=true, skipped=true, aborted=true}
}
local snapshot_transition = ARGV[14] == '1'
local old_terminal = old_status == 'succeeded' or old_status == 'failed' or old_status == 'skipped' or old_status == 'aborted'
if old_status ~= new_status
    and not (allowed[old_status] and allowed[old_status][new_status])
    and not (snapshot_transition and not old_terminal) then
    return {-1, 'invalid', old_revision}
end

if ARGV[9] == '1' and old_status ~= new_status then
    redis.call('HINCRBY', KEYS[3], old_status, -1)
    redis.call('HINCRBY', KEYS[3], new_status, 1)
end
redis.call('HSET', KEYS[1], task_id, new_status)
redis.call('HSET', KEYS[2], task_id, ARGV[8])
redis.call('HSET', KEYS[3], 'updated_at', ARGV[7])
if ARGV[10] ~= '' then redis.call('HSET', KEYS[3], 'current_stage_id', ARGV[10]) end
if ARGV[11] ~= '' then redis.call('HSET', KEYS[3], 'current_job_id', ARGV[11]) end
if ARGV[12] ~= '' then redis.call('HSET', KEYS[3], 'current_skill_id', ARGV[12]) end

local event_id = redis.call(
    'XADD', KEYS[4], 'MAXLEN', '~', tonumber(ARGV[13]), '*',
    'type', ARGV[6],
    'task_id', task_id,
    'status', new_status,
    'phase', ARGV[4],
    'reason', ARGV[5],
    'occurred_at', ARGV[7],
    'revision', ARGV[2],
    'data', ARGV[8]
)
redis.call('HSET', KEYS[3], 'last_event_id', event_id)
return {1, event_id, revision}
"""


RUN_TRANSITION_LUA = r"""
local revision = tonumber(ARGV[1])
local new_status = ARGV[2]
local old_status = redis.call('HGET', KEYS[1], 'status') or 'starting'
local old_revision = tonumber(redis.call('HGET', KEYS[1], 'run_revision')) or 0
if revision <= old_revision then
    return {0, 'stale', old_revision}
end

local allowed = {
    queued = {starting=true, failed=true, aborted=true},
    starting = {running=true, failed=true, aborted=true, stale=true},
    running = {succeeded=true, failed=true, aborted=true, stale=true},
    stale = {running=true, failed=true, aborted=true}
}
local snapshot_transition = ARGV[8] == '1'
local old_terminal = old_status == 'succeeded' or old_status == 'failed' or old_status == 'aborted'
if old_status ~= new_status
    and not (allowed[old_status] and allowed[old_status][new_status])
    and not (snapshot_transition and not old_terminal) then
    return {-1, 'invalid', old_revision}
end

redis.call(
    'HSET', KEYS[1],
    'status', new_status,
    'run_revision', revision,
    'updated_at', ARGV[4]
)
if new_status == 'running' then
    redis.call('SADD', KEYS[2], ARGV[6])
    redis.call('HSETNX', KEYS[1], 'started_at', ARGV[4])
elseif new_status == 'succeeded' or new_status == 'failed' or new_status == 'aborted' then
    redis.call('SREM', KEYS[2], ARGV[6])
    redis.call('HSET', KEYS[1], 'finished_at', ARGV[4])
end

local event_id = redis.call(
    'XADD', KEYS[3], 'MAXLEN', '~', tonumber(ARGV[7]), '*',
    'type', ARGV[3],
    'status', new_status,
    'occurred_at', ARGV[4],
    'revision', ARGV[1],
    'data', ARGV[5]
)
redis.call('HSET', KEYS[1], 'last_event_id', event_id)
return {1, event_id, revision}
"""


FINALIZE_RUN_LUA = r"""
local old_status = redis.call('HGET', KEYS[1], 'status')
local old_terminal = old_status == 'succeeded' or old_status == 'failed' or old_status == 'aborted'
if old_terminal and old_status ~= ARGV[1] then
    return {0, old_status}
end

local summary = cjson.decode(ARGV[3])
for key, value in pairs(summary) do
    redis.call('HSET', KEYS[1], key, tostring(value))
end
redis.call(
    'HSET', KEYS[1],
    'status', ARGV[1],
    'finished_at', ARGV[2],
    'updated_at', ARGV[2]
)
redis.call('SREM', KEYS[2], ARGV[4])
return {1, ARGV[1]}
"""


SUBMIT_RUN_LUA = r"""
if redis.call('HEXISTS', KEYS[3], 'status') == 1 then
    return {0, 'run_exists'}
end

local run_id = ARGV[1]
local created_at = ARGV[2]
local score = tonumber(ARGV[3])
local payload = cjson.decode(ARGV[4])
local maxlen = tonumber(ARGV[5])
local entry_id = redis.call(
    'XADD', KEYS[1], '*',
    'run_id', run_id,
    'gamever', payload.gamever,
    'platforms', payload.platforms,
    'modules', payload.modules,
    'skill_filter', payload.skill_filter,
    'agent', payload.agent,
    'created_at', created_at
)

redis.call('ZADD', KEYS[2], 'NX', score, run_id)
redis.call(
    'HSET', KEYS[3],
    'status', 'queued',
    'gamever', payload.gamever,
    'agent', payload.agent,
    'created_at', created_at,
    'updated_at', created_at,
    'queue_entry_id', entry_id,
    'total', 0,
    'pending', 0,
    'running', 0,
    'succeeded', 0,
    'failed', 0,
    'skipped', 0,
    'aborted', 0,
    'run_revision', 0
)
local event_id = redis.call(
    'XADD', KEYS[4], 'MAXLEN', '~', maxlen, '*',
    'type', 'run.queued',
    'run_id', run_id,
    'status', 'queued',
    'occurred_at', created_at,
    'revision', '0',
    'data', ARGV[4]
)
redis.call('HSET', KEYS[3], 'last_event_id', event_id)
return {1, entry_id, event_id}
"""


SCHEDULER_RUN_TRANSITION_LUA = r"""
local old_status = redis.call('HGET', KEYS[1], 'status')
local new_status = ARGV[2]
if not old_status then
    return {-2, 'missing_run'}
end
if old_status == 'succeeded' or old_status == 'failed' or old_status == 'aborted' then
    return {0, old_status}
end

local allowed = {
    queued = {starting=true, failed=true, aborted=true},
    starting = {succeeded=true, failed=true, aborted=true},
    running = {succeeded=true, failed=true, aborted=true},
    stale = {succeeded=true, failed=true, aborted=true}
}
if old_status ~= new_status and not (allowed[old_status] and allowed[old_status][new_status]) then
    return {-1, 'invalid_transition'}
end

redis.call(
    'HSET', KEYS[1],
    'status', new_status,
    'updated_at', ARGV[3],
    'scheduler_consumer', ARGV[4],
    'queue_entry_id', ARGV[5]
)
if new_status == 'starting' then
    redis.call('HSETNX', KEYS[1], 'scheduler_started_at', ARGV[3])
elseif new_status == 'succeeded' or new_status == 'failed' or new_status == 'aborted' then
    local task_rows = redis.call('HGETALL', KEYS[5])
    local summary = {pending=0, running=0, succeeded=0, failed=0, skipped=0, aborted=0}
    local total = 0
    for index = 1, #task_rows, 2 do
        local task_id = task_rows[index]
        local ok, task = pcall(cjson.decode, task_rows[index + 1])
        if ok and task then
            local task_status = task.status or 'pending'
            if task_status == 'pending' or task_status == 'running' then
                task_status = 'aborted'
                task.status = task_status
                task.phase = 'finished'
                task.reason = 'upstream_aborted'
                task.error = ARGV[7] ~= '' and ARGV[7] or cjson.null
                task.updated_at = ARGV[3]
                task.finished_at = ARGV[3]
                task.event_type = 'task.status_changed'
                task.revision = (tonumber(task.revision) or 0) + 1
                local task_json = cjson.encode(task)
                redis.call('HSET', KEYS[4], task_id, task_status)
                redis.call('HSET', KEYS[5], task_id, task_json)
                local task_event_id = redis.call(
                    'XADD', KEYS[3], 'MAXLEN', '~', tonumber(ARGV[8]), '*',
                    'type', 'task.status_changed',
                    'task_id', task_id,
                    'status', task_status,
                    'phase', 'finished',
                    'reason', 'upstream_aborted',
                    'occurred_at', ARGV[3],
                    'revision', tostring(task.revision),
                    'data', task_json
                )
                redis.call('HSET', KEYS[1], 'last_event_id', task_event_id)
            end
            if task.task_type ~= 'job' and summary[task_status] ~= nil then
                summary[task_status] = summary[task_status] + 1
                total = total + 1
            end
        end
    end
    redis.call(
        'HSET', KEYS[1],
        'total', total,
        'pending', summary.pending,
        'running', summary.running,
        'succeeded', summary.succeeded,
        'failed', summary.failed,
        'skipped', summary.skipped,
        'aborted', summary.aborted
    )
    redis.call(
        'HSET', KEYS[1],
        'finished_at', ARGV[3],
        'scheduler_exit_code', ARGV[6],
        'error_summary', ARGV[7]
    )
    redis.call('SREM', KEYS[2], ARGV[1])
end

local event_id = redis.call(
    'XADD', KEYS[3], 'MAXLEN', '~', tonumber(ARGV[8]), '*',
    'type', 'run.status_changed',
    'status', new_status,
    'occurred_at', ARGV[3],
    'revision', redis.call('HGET', KEYS[1], 'run_revision') or '0',
    'data', cjson.encode({
        status=new_status,
        scheduler_consumer=ARGV[4],
        queue_entry_id=ARGV[5],
        exit_code=ARGV[6],
        error=ARGV[7]
    })
)
redis.call('HSET', KEYS[1], 'last_event_id', event_id)
return {1, event_id}
"""


RENEW_SCHEDULER_LEASE_LUA = r"""
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return 0
end
return redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
"""


RELEASE_SCHEDULER_LEASE_LUA = r"""
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return 0
end
return redis.call('DEL', KEYS[1])
"""
