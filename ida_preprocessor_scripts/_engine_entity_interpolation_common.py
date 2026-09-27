"""Current ELF identities for the entity-linking functions in issue #266."""

from pathlib import Path


SVEN_8948_LINUX_NAMES = {
    "CL_LinkPacketEntities": "_Z21CL_LinkPacketEntitiesv",
    "CL_InterpolateModel": "_Z19CL_InterpolateModelP11cl_entity_s",
    "CL_FindInterpolationUpdates": "_Z27CL_FindInterpolationUpdatesP11cl_entity_sfPP18position_history_tS3_Pi",
}


def function_identity(new_binary_dir, platform, source_name):
    """Use the real ELF name where one exists; keep source identity on stripped inputs."""
    gamever = Path(new_binary_dir).parent.name
    if platform == "linux" and gamever == "svencoop-8948":
        return SVEN_8948_LINUX_NAMES.get(source_name, source_name)
    return source_name
