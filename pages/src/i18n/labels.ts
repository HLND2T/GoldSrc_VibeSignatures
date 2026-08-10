import type { TFunction } from 'i18next'

export function statusLabel(status: string, t: TFunction): string {
  return t(`status.${status}`, { defaultValue: status })
}

export function phaseLabel(phase: string, t: TFunction): string {
  return t(`phase.${phase}`, { defaultValue: phase })
}
