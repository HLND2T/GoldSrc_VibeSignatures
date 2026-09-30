"""Static declarations are parsed without executing analysis scripts."""

import unittest

from gamesymbol_snapshot_lib.analysis_sources import _source_metadata


class ImportResolutionTests(unittest.TestCase):
    def test_package_children_aliases_attributes_and_cycles(self):
        root = "ida_preprocessor_scripts/"
        tree = {
            root
            + "find-demo.py": "from ida_preprocessor_scripts import helper as h, other\nfrom ida_preprocessor_scripts.pkg import helper, VALUE\n",
            root + "helper.py": "from . import other\n",
            root + "other.py": "from .helper import function\n",
            root + "pkg/__init__.py": "VALUE = 1\n",
            root + "pkg/helper.py": "from .. import other\n",
        }
        self.assertEqual(
            {root + p for p in ("helper.py", "other.py", "pkg/__init__.py", "pkg/helper.py")},
            _source_metadata(root + "find-demo.py", tree)[0],
        )
        self.assertEqual({root + "other.py"}, _source_metadata(root + "pkg/helper.py", tree)[0])
        self.assertEqual({root + "helper.py"}, _source_metadata(root + "other.py", tree)[0])

    def test_package_initializers_star_and_real_attribute_imports(self):
        root = "ida_preprocessor_scripts/"
        tree = {
            root
            + "find-demo.py": "import ida_preprocessor_scripts.pkg.child\nfrom ida_preprocessor_scripts.pkg import VALUE\nfrom ida_preprocessor_scripts.pkg import *\n",
            root + "__init__.py": "",
            root + "pkg/__init__.py": "VALUE=1\n",
            root + "pkg/child.py": "raise RuntimeError('must not execute')",
        }
        self.assertEqual(
            {root + p for p in ("__init__.py", "pkg/__init__.py", "pkg/child.py")},
            _source_metadata(root + "find-demo.py", tree)[0],
        )
        self.assertFalse(any("VALUE" in p for p in _source_metadata(root + "find-demo.py", tree)[0]))


class DeclarationTests(unittest.TestCase):
    def spec(self, symbol="Target"):
        return dict(
            symbol_name=symbol,
            prompt_path="prompt/call_llm_decompile.md",
            reference_yaml_paths=["references/{gamever}/engine/Owner.{platform}.yaml"],
            expected_result_sections=["found_call"],
            dependency_policy={"Owner.{platform}.yaml": "required"},
        )

    def parse(self, source):
        from llm_declarations import parse_declaration

        return parse_declaration(source, "ida_preprocessor_scripts/find-demo.py")

    def test_literal_branches_allow_same_symbol(self):
        declaration = {"normal": [self.spec()], "inline": [self.spec()]}
        self.assertEqual(declaration, self.parse("LLM_DECOMPILE = " + repr(declaration)))

    def test_rejects_nonliteral_duplicate_and_invalid_schema(self):
        good = "LLM_DECOMPILE = " + repr([self.spec()])
        invalid = [
            "LLM_DECOMPILE = build_specs()",
            "LLM_DECOMPILE = [spec for spec in OTHER]",
            good + "\nLLM_DECOMPILE = []",
            "if True:\n    " + good,
            good + "\nLLM_DECOMPILE.append({})",
            good + '\ncopy = LLM_DECOMPILE\ncopy[0]["symbol_name"] = "Other"',
            good + '\nLLM_DECOMPILE[0].update(symbol_name="Other")',
            'LLM_DECOMPILE = [{"symbol_name": "A", "symbol_name": "B"}]',
            "LLM_DECOMPILE = " + repr([self.spec(), self.spec()]),
        ]
        for field, value in [
            ("prompt_path", "../prompt/a.md"),
            ("reference_yaml_paths", ["references/{unknown}/a.yaml"]),
            ("reference_yaml_paths", ["references/{{gamever}}/a.yaml"]),
            ("reference_yaml_paths", ["references/{gamever!s}/a.yaml"]),
            ("reference_yaml_paths", ["references/../a.yaml"]),
            ("expected_value", -1),
            ("instruction_rules", [{"regex": "[", "text": "invalid"}]),
            ("expected_result_sections", ["invalid"]),
            ("dependency_policy", {}),
            ("expected_size", True),
        ]:
            invalid.append("LLM_DECOMPILE = " + repr([{**self.spec(), field: value}]))
        for source in invalid:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "find-demo.py:"):
                self.parse(source)

    def test_sink_requires_declaration_including_kwargs(self):
        for source in (
            "async def preprocess_skill():\n    await run(llm_decompile_specs=[])",
            'async def preprocess_skill():\n    opts = {"llm_decompile_specs": []}\n    await run(**opts)',
        ):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "LLM_DECOMPILE"):
                self.parse(source)

    def test_literal_declaration_cannot_mask_dynamic_sink(self):
        with self.assertRaises(ValueError):
            self.parse(
                "LLM_DECOMPILE = "
                + repr([self.spec()])
                + "\nasync def preprocess_skill():\n    await run(llm_decompile_specs=build_specs())"
            )


class SelectionTests(unittest.TestCase):
    def test_runtime_overlays_preserve_dependencies_and_do_not_mutate_declaration(self):
        from copy import deepcopy
        from llm_spec import select_llm_specs

        spec = DeclarationTests().spec()
        declaration = {
            "a": [spec, {**spec, "symbol_name": "Second"}],
            "b": [{**spec, "prompt_path": "prompt/other.md"}],
        }
        before = deepcopy(declaration)
        rules = [{"regex": "mov.*", "text": "verified instruction"}]
        selected = select_llm_specs(
            declaration,
            branch="a",
            symbols=["Second", "Target"],
            expected_values={"Second": 123},
            instruction_rules={"Target": rules},
        )
        self.assertEqual(["Second", "Target"], [v["symbol_name"] for v in selected])
        self.assertEqual(123, selected[0]["expected_value"])
        self.assertEqual(rules, selected[1]["instruction_rules"])
        selected[0]["reference_yaml_paths"].append("not-a-real-reference")
        self.assertEqual(before, declaration)
        self.assertEqual("prompt/other.md", select_llm_specs(declaration, branch="b")[0]["prompt_path"])
        with self.assertRaises(KeyError):
            select_llm_specs(declaration, branch="a", symbols=["Unknown"])
        with self.assertRaises(TypeError):
            select_llm_specs(declaration, reference_yaml_paths=["dynamic"])


class DeclarationUsageTests(DeclarationTests):
    def test_unsupported_mutation_and_indirection_fail_closed(self):
        good = (
            "from llm_spec import select_llm_specs\nfrom ida_analyze_util import preprocess_common_skill as run\nLLM_DECOMPILE = "
            + repr([self.spec()])
            + "\n"
        )
        invalid = [
            "for spec in LLM_DECOMPILE:\n    spec['reference_yaml_paths'] = []",
            "specs: list = LLM_DECOMPILE\nspecs.clear()",
            "alias = LLM_DECOMPILE\nalias += []\nalias[0]['symbol_name'] = 'Other'",
            "modify(LLM_DECOMPILE)",
            "specs = [*LLM_DECOMPILE]\nspecs[0]['prompt_path'] = dynamic",
            "field = 'prompt_path'\nspecs = [*LLM_DECOMPILE]\nspecs[0][field] = dynamic",
            "field = 'prompt_path'\nfor (spec,) in [(LLM_DECOMPILE[0],)]:\n    spec[field] = dynamic",
            "run(llm_decompile_specs=[LLM_DECOMPILE[0], dynamic])",
            "box = {'value': LLM_DECOMPILE}\nspecs = box['value']\nspecs[0]['reference_yaml_paths'] = dynamic",
            "box = (LLM_DECOMPILE,)\nbox[0][0]['dependency_policy'] = dynamic",
            "spec, = LLM_DECOMPILE\nspec['prompt_path'] = dynamic",
            "[spec] = LLM_DECOMPILE\nspec['prompt_path'] = dynamic",
            "async def forward(*, llm_decompile_specs):\n    await run(llm_decompile_specs=llm_decompile_specs)\nKEY = 'llm_decompile_specs'\nforward(**{KEY: dynamic})",
            "from ida_preprocessor_scripts.helper import forward\nKEY = 'llm_decompile_specs'\nforward(**{KEY: dynamic})",
            "from ida_analyze_util import *\nKEY = 'llm_decompile_specs'\npreprocess_common_skill(**{KEY: dynamic})",
            "LLM_DECOMPILE = [*LLM_DECOMPILE]",
            "run(llm_decompile_specs=select_llm_specs(LLM_DECOMPILE, **overrides))",
            "select_llm_specs = evil\nrun(llm_decompile_specs=select_llm_specs(LLM_DECOMPILE))",
            "def select_llm_specs(declaration):\n    return dynamic\nrun(llm_decompile_specs=select_llm_specs(LLM_DECOMPILE))",
            "def helper(select_llm_specs):\n    run(llm_decompile_specs=select_llm_specs(LLM_DECOMPILE))",
            "def helper(LLM_DECOMPILE):\n    run(llm_decompile_specs=LLM_DECOMPILE)",
            "from other import LLM_DECOMPILE",
            "def helper(*, llm_decompile_specs=dynamic):\n    run(llm_decompile_specs=llm_decompile_specs)",
            "run(**build_kwargs())",
            "kwargs = {'llm_decompile_specs': LLM_DECOMPILE}\nother = kwargs\nother.update(extra)\nrun(**kwargs)",
            "kwargs = {}\nkwargs['llm_decompile_specs'] = dynamic\nrun(**kwargs)",
            "run(*args)",
            "def helper(*, llm_decompile_specs):\n    llm_decompile_specs[0]['symbol_name'] = 'Other'",
        ]
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.parse(good + source)

    def test_alias_kwargs_branch_and_forwarding_grammar(self):
        declaration = {"one": [self.spec()], "two": [self.spec()]}
        source = (
            "from llm_spec import select_llm_specs as select\nfrom ida_analyze_util import preprocess_common_skill as run\nLLM_DECOMPILE = "
            + repr(declaration)
            + "\n"
        )
        source += """
async def preprocess_skill():
    selected = select(LLM_DECOMPILE, branch=branch, expected_values=verified)
    kwargs = {'llm_decompile_specs': selected}
    await run(**kwargs)
async def helper(*, llm_decompile_specs):
    await run(llm_decompile_specs=llm_decompile_specs)
"""
        self.assertEqual(declaration, self.parse(source))

    def test_no_script_execution(self):
        self.assertEqual(
            [self.spec()], self.parse("raise RuntimeError('must not run')\nLLM_DECOMPILE = " + repr([self.spec()]))
        )


class BranchOwnershipTests(unittest.TestCase):
    def test_branch_union_shared_consumers_cycles_and_runtime_import(self):
        from types import SimpleNamespace
        from gamesymbol_snapshot_lib.analysis_sources import build_source_index

        root = "ida_preprocessor_scripts/"
        nodes = {
            name: SimpleNamespace(node_id=name, skill_name=name, platform="windows", module_name="engine")
            for name in ("first", "second")
        }
        declaration = {
            "one": [DeclarationTests().spec()],
            "two": [
                {**DeclarationTests().spec(), "reference_yaml_paths": ["references/other/engine/Owner.windows.yaml"]}
            ],
        }
        tree = {
            root + "first.py": "from ida_preprocessor_scripts import helper",
            root + "second.py": "from ida_preprocessor_scripts import helper as renamed",
            root + "helper.py": "from . import cycle\nfrom llm_spec import select_llm_specs\nLLM_DECOMPILE = "
            + repr(declaration),
            root + "cycle.py": "from . import helper",
            "llm_spec.py": 'raise RuntimeError("must not execute")',
            root + "references/game-1/engine/Owner.windows.yaml": "current",
            root + "references/hl-10210/engine/Owner.windows.yaml": "default",
            root + "references/other/engine/Owner.windows.yaml": "other branch",
            root + "prompt/call_llm_decompile.md": "prompt",
        }
        index = build_source_index(SimpleNamespace(game_version="game-1", nodes=nodes), tree)
        self.assertFalse(index.conservative_resource_owners)
        for path in (
            "helper.py",
            "cycle.py",
            "references/game-1/engine/Owner.windows.yaml",
            "references/other/engine/Owner.windows.yaml",
            "prompt/call_llm_decompile.md",
        ):
            self.assertEqual(frozenset(nodes), index.owners(root + path))
        self.assertEqual(frozenset(nodes), index.owners("llm_spec.py"))
        self.assertFalse(index.owners(root + "references/hl-10210/engine/Owner.windows.yaml"))
