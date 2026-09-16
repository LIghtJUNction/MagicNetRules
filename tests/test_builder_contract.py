"""Behavioral safety regressions independent of an installed compiler."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('builder', Path(__file__).resolve().parents[1] / 'scripts/builder.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class BuilderContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sources = self.root / 'sources'
        self.sources.mkdir()
        self.dist = self.root / 'dist'
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'standalone_sources':['sample']}))
        self.write_source([{'domain':['example.com']}])
        self.paths = patch.multiple(builder, SOURCES_DIR=self.sources, DIST_DIR=self.dist,
            CONFIG_PATH=self.config, BINARY_DIR=self.root/'binary')
        self.paths.start()
        self.addCleanup(self.paths.stop)
        def compile_fixture(source, target):
            target.write_bytes(b'SRS' + hashlib.sha256(source.read_bytes()).digest())
        self.compiler = patch.object(builder, 'compile_ruleset', side_effect=compile_fixture)
        self.compiler.start()
        self.addCleanup(self.compiler.stop)

    def write_source(self, rules):
        (self.sources/'sample.json').write_text(json.dumps({'version':2, 'rules':rules}))

    def snapshot(self):
        return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def test_leading_dot_does_not_cover_apex(self):
        value = builder.optimize_rule_components({'example.com','a.example.com'}, {'.example.com'},set(),set(),set())
        self.assertEqual(value, {'domain':['example.com'],'domain_suffix':['.example.com']})

    def test_suffix_marker_cannot_collide_with_domain_label(self):
        trie = builder.DomainTrie()
        self.assertTrue(trie.insert_suffix('_term.example'))
        self.assertFalse(trie.matches('other.example'))
        self.assertTrue(trie.matches('_term.example'))

    def test_inclusive_suffix_supersedes_subdomain_only(self):
        result=builder.optimize_rule_components(set(),{'.example.com','example.com','a.example.com'},set(),set(),set())
        self.assertEqual(result['domain_suffix'],['example.com'])

    def test_constraints_inversion_and_logical_rules_are_preserved(self):
        rules=[{'domain':['private.example'],'network':'tcp','port':443},
               {'domain_suffix':['example.org'],'invert':True},
               {'type':'logical','mode':'and','rules':[{'domain':['a.test']},{'network':'udp'}]}]
        self.write_source(rules)
        result,_=builder.merge_and_optimize_sources(['sample'])
        self.assertEqual(result['rules'], rules)

    def test_regex_whitespace_is_not_rewritten(self):
        self.write_source([{'domain_regex':[' foo ']}])
        result,_=builder.merge_and_optimize_sources(['sample'])
        self.assertEqual(result['rules'][0]['domain_regex'],[' foo '])

    def test_invalid_cidr_fails_instead_of_disappearing(self):
        with self.assertRaises(ValueError): builder.IpOptimizer.optimize(['10.0.0.0/8','invalid'])

    def test_duplicate_json_keys_fail(self):
        (self.sources/'sample.json').write_text('{"version":2,"rules":[],"rules":[{}]}')
        with self.assertRaises(ValueError): builder.load_source_rules('sample')

    def test_invalid_source_shape_and_values_fail(self):
        for rules in ([{}], [{'domain':[1]}], [{'domain':[]}], ['bad']):
            self.write_source(rules)
            with self.subTest(rules=rules), self.assertRaises(ValueError): builder.merge_and_optimize_sources(['sample'])

    def test_check_does_not_create_missing_outputs(self):
        before=self.snapshot()
        with self.assertRaises(AssertionError): builder.build_all(check=True)
        self.assertEqual(self.snapshot(),before)
        self.assertFalse(self.dist.exists())

    def test_check_is_read_only_and_rejects_tampered_srs(self):
        builder.build_all()
        builder.build_all(check=True)
        target=self.dist/'sample.srs'
        target.write_bytes(b'SRSinvalid')
        before=self.snapshot()
        with self.assertRaises(AssertionError): builder.build_all(check=True)
        self.assertEqual(self.snapshot(),before)

    def test_check_rejects_missing_and_extra_files_without_repair(self):
        builder.build_all()
        (self.dist/'sample.json').unlink()
        (self.dist/'junk').write_text('junk')
        before=self.snapshot()
        with self.assertRaises(AssertionError): builder.build_all(check=True)
        self.assertEqual(self.snapshot(),before)

    def test_failed_compile_preserves_previous_dist(self):
        builder.build_all()
        self.write_source([{'domain':['new.example']}])
        before=self.snapshot()
        with patch.object(builder,'compile_ruleset',side_effect=RuntimeError('compiler failed')):
            with self.assertRaises(RuntimeError): builder.build_all()
        self.assertEqual(self.snapshot(),before)

    def test_deterministic_build_removes_stale_outputs(self):
        builder.build_all()
        before=self.snapshot()
        (self.dist/'stale.srs').write_bytes(b'SRS')
        builder.build_all()
        self.assertEqual(self.snapshot(),before)

    def test_duplicate_and_unsafe_targets_fail(self):
        for cfg in ({'standalone_sources':['sample','sample']}, {'standalone_sources':['../sample']}):
            self.config.write_text(json.dumps(cfg))
            with self.subTest(cfg=cfg), self.assertRaises(ValueError): builder.build_all()
