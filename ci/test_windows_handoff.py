"""Exercise the actual pure handoff configuration without Windows maintenance side effects."""
import ast, pathlib, unittest
source = pathlib.Path(__file__).with_name('windows_authorized_full.py')
tree = ast.parse(source.read_text())
function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'configure_handoff')
namespace = {}
exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
configure = namespace['configure_handoff']

class HandoffTests(unittest.TestCase):
    def test_default_removes_injected_alias_and_never_enables_adapter(self):
        original = {'network_handoff_alias': 'Ethernet', 'target': 'fixture'}
        for adapters in ([], ['Ethernet'], ['Ethernet', 'Wi-Fi']):
            data, recovery = configure(original, adapters, False)
            self.assertNotIn('network_handoff_alias', data)
            self.assertEqual(recovery, '')
            self.assertEqual(data['target'], 'fixture')
        self.assertEqual(original['network_handoff_alias'], 'Ethernet')

    def test_opt_in_requires_one_known_adapter(self):
        for adapters in ([], ['Ethernet', 'Wi-Fi']):
            with self.assertRaises(ValueError): configure({}, adapters, True)

    def test_opt_in_escapes_recovery_alias(self):
        data, recovery = configure({}, ["User's Ethernet"], True)
        self.assertEqual(data['network_handoff_alias'], "User's Ethernet")
        self.assertIn("'User''s Ethernet'", recovery)

if __name__ == '__main__': unittest.main()
