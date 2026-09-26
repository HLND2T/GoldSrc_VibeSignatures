#!/usr/bin/env python3
"""Locate Sven's CParticleSystem::ParticleDraw(CParticleUnit*) by its diagnostic.

The sprite lookup failure belongs to ParticleDraw itself, not DrawPortals.
The full literal has one instance and one direct xref owner on both platforms
of svencoop-8948 and svencoop-10257. The 8948 ELF symbol is
_ZN15CParticleSystem12ParticleDrawEP13CParticleUnit; the newer stripped build
retains the same sprite lookup, particle billboard and colour/alpha behaviour.
"""

from ida_analyze_util import preprocess_common_skill

TARGET = "CParticleSystem_ParticleDraw"
FUNC_XREFS = [
    {
        "func_name": TARGET,
        "xref_strings": ['FULLMATCH:Particle_Engine: Couldn\'t get sprite pointer for "%s"!\n'],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [(TARGET, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
