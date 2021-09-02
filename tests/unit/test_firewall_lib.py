# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Rich Megginson <rmeggins@redhat.com>
# SPDX-License-Identifier: GPL-2.0-or-later
#
""" Unit tests for kernel_settings module """

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import unittest

try:
    from unittest.mock import Mock, patch
except ImportError:
    from mock import Mock, patch

import firewall_lib


class MockException(Exception):
    pass


class AddServiceException(Exception):
    pass


class MockFirewallClient(object):
    def __init__(self):
        self.connected = False

    def __call__(self):
        return self

    def set_params(self, connected_value):
        self.connected = connected_value

    def setExceptionHandler(self, error):
        pass

    def getDefaultZone(self):
        return "default"

    def config(self):
        return MockFirewallConfig()

    def queryService(self, zone, item):
        return False

    def addService(self, zone, item, timeout):
        raise AddServiceException()

    def addPort(self, zone, port, protocol, timeout):
        raise MockException("called addPort")

    def queryPort(self, zone, port, protocol):
        return False

    def querySourcePort(self, zone, port, protocol):
        return False

    def addSourcePort(self, zone, port, protocol, timeout):
        raise MockException("called addSourcePort")

    def queryForwardPort(self, zone, port, protocol, to_port, to_addr):
        return False

    def addForwardPort(self, zone, port, protocol, to_port, to_addr, timeout):
        raise MockException("called addForwardPort")

    def queryMasquerade(self, zone):
        return False

    def addMasquerade(self, zone, timeout):
        raise MockException("called addMasquerade")

    # def queryRichRule(self,zone,item):
    # return False
    # def addRichRule(self,zone,item,timout):
    # return MockException("called addRichRule")


class MockFirewallConfig:
    def getZoneByName(self, zone):
        return MockFirewallZone()


class MockFirewallZone:
    def getSettings(self):
        return MockFirewallSettings


class MockFirewallSettings:
    def queryService(item):
        return True

    def queryPort(port, protocol):
        return True

    def removeService(item):
        raise MockException("called removeService")

    def removePort(port, protocol):
        raise MockException("called removePort")

    def querySourcePort(port, protocol):
        return True

    def removeSourcePort(port, protocol):
        raise MockException("called removeSourcePort")

    def queryForwardPort(port, protocol):
        return True

    def removeForwardPort(port, protocol, to_port, to_addr):
        raise MockException("called removeForwardPort")

    def queryMasquerade():
        return True

    def removeMasquerade():
        raise MockException("called removeMasquerade")


class MockAnsibleModule(object):
    def __init__(self, **kwargs):
        self.check_mode = False
        self.params = {}
        self.call_params = {}
        if not kwargs:
            return
        if "name" in kwargs:
            self.name = kwargs["name"]
            return

    def __call__(self, **kwargs):
        for kk, vv in kwargs["argument_spec"].items():
            self.call_params[kk] = vv.get("default")
            if kk not in self.params:
                self.params[kk] = self.call_params[kk]
        self.supports_check_mode = kwargs["supports_check_mode"]
        return self

    def set_params(self, params):
        self.params = params

    def fail_json(self, msg):
        self.fail_msg = msg
        raise MockException()


class FirewallLibParsers(unittest.TestCase):
    """test param to profile conversion and vice versa"""

    # def assertRegex(self, text, expected_regex, msg=None):
    #     """Fail the test unless the text matches the regular expression."""
    #     assert re.search(expected_regex, text)

    # def setUp(self):
    #     self.test_root_dir = tempfile.mkdtemp(suffix=".lsr")
    #     os.environ["TEST_ROOT_DIR"] = self.test_root_dir
    #     self.test_cleanup = kernel_settings.setup_for_testing()
    #     self.tuned_config = tuned.utils.global_config.GlobalConfig()
    #     self.logger = Mock()

    # def tearDown(self):
    #     self.test_cleanup()
    #     shutil.rmtree(self.test_root_dir)
    #     del os.environ["TEST_ROOT_DIR"]

    def test_parse_port(self):
        """Test the code that parses port values."""

        module = Mock()
        item = "a/b"
        rc = firewall_lib.parse_port(module, item)
        self.assertEqual(("a", "b"), rc)

    def test_parse_forward_port(self):
        """Test the code that parses port values."""

        module = Mock()
        module.fail_json = Mock(side_effect=MockException())
        item = "aaa"
        with self.assertRaises(MockException):
            rc = firewall_lib.parse_forward_port(module, item)
        module.fail_json.assert_called_with(msg="improper forward_port format: aaa")
        item = "a/b;;"
        rc = firewall_lib.parse_forward_port(module, item)
        self.assertEqual(("a", "b", None, None), rc)


class FirewallLibMain(unittest.TestCase):
    """Test main function."""

    @patch("firewall_lib.AnsibleModule")
    def test_main_error_no_firewall_backend(self, module_class):
        module_class.return_value.fail_json = Mock(side_effect=MockException())
        with self.assertRaises(MockException):
            firewall_lib.main()
        module_class.return_value.fail_json.assert_called_with(
            msg="No firewall backend could be imported."
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_no_params(self, am_class):
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg,
            "One of service, port, source_port, forward_port, masquerade, rich_rule, source, "
            "interface, icmp_block, icmp_block_inversion, target or zone needs to be set",
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_icmp_block_inversion(self, am_class):
        am_class.set_params({"icmp_block_inversion": True, "timeout": 1})
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg, "timeout can not be used with icmp_block_inverson only"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_source(self, am_class):
        am_class.set_params({"source": ["192.0.2.0/24"], "timeout": 1})
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(am_class.fail_msg, "timeout can not be used with source only")

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_permanent_runtime_offline(self, am_class):
        am_class.set_params(
            {
                "icmp_block_inversion": True,
                "permanent": False,
                "runtime": False,
                "offline": False,
            }
        )
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg,
            "One of permanent, runtime or offline needs to be enabled",
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_timeout_with_disabled_state(self, am_class):
        am_class.set_params(
            {"source": ["192.0.2.0/24"], "state": "disabled", "timeout": 1}
        )
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg, "timeout can not be used with state: disabled"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_masquerade_with_disabled_state(self, am_class):
        am_class.set_params(
            {"source": ["192.0.2.0/24"], "state": "disabled", "masquerade": True}
        )
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg, "masquerade can not be used with state: disabled"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_icmp_block_inversion_with_disabled_state(self, am_class):
        am_class.set_params(
            {
                "source": ["192.0.2.0/24"],
                "state": "disabled",
                "icmp_block_inversion": True,
            }
        )
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg,
            "icmp_block_inversion can not be used with state: disabled",
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_interface(self, am_class):
        am_class.set_params({"interface": ["eth2"], "timeout": 1})
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg, "timeout can not be used with interface only"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_target(self, am_class):
        am_class.set_params({"timeout": 1, "target": ""})
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(am_class.fail_msg, "timeout can not be used with target only")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_firewalld_running(self, am_class, firewall_class):
        am_class.set_params(
            {
                "icmp_block_inversion": True,
                "permanent": False,
                "runtime": True,
                "offline": False,
            }
        )
        firewall_class.set_params(False)
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg,
            "Firewalld is not running and offline operation is declined.",
        )

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    def test_firewalld_offline_version_disconnected(self, am_class, firewall_class):
        am_class.set_params(
            {
                "icmp_block_inversion": True,
                "permanent": False,
                "offline": True,
            }
        )
        firewall_class.set_params(False)
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg,
            "Unsupported firewalld version 0.3.8, offline operation requires >= 0.3.9",
        )

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.2.8", create=True)
    def test_firewalld_offline_version_connected(self, am_class, firewall_class):
        am_class.set_params(
            {
                "icmp_block_inversion": True,
                "permanent": False,
                "offline": True,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException):
            firewall_lib.main()
        self.assertEqual(
            am_class.fail_msg,
            "Unsupported firewalld version 0.2.8, requires >= 0.2.11",
        )

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_service_enabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": False,
                "offline": True,
                "service": ["default", "internal", "dmz"],
                "state": "enabled",
                "runtime": True,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(AddServiceException):
            firewall_lib.main()

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_service_disabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": True,
                "offline": True,
                "service": ["default", "internal", "dmz"],
                "state": "disabled",
                "runtime": False,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called removeService")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_port_enabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": False,
                "offline": True,
                "port": ["8081/tcp", "161-162/udp"],
                "state": "enabled",
                "runtime": True,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called addPort")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_port_disabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": True,
                "offline": True,
                "port": ["8081/tcp", "161-162/udp"],
                "state": "disabled",
                "runtime": False,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called removePort")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_source_port_enabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": False,
                "offline": True,
                "source_port": ["8081/tcp", "161-162/udp"],
                "state": "enabled",
                "runtime": True,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called addSourcePort")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_source_port_disabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": True,
                "offline": True,
                "source_port": ["8081/tcp", "161-162/udp"],
                "state": "disabled",
                "runtime": False,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called removeSourcePort")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_forward_port_enabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": False,
                "offline": True,
                "forward_port": ["8081/tcp", "161-162/udp"],
                "state": "enabled",
                "runtime": True,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called addForwardPort")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_forward_port_disabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": True,
                "offline": True,
                "forward_port": ["8081/tcp", "161-162/udp"],
                "state": "disabled",
                "runtime": False,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called removeForwardPort")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_masquerade_enabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": False,
                "offline": True,
                "masquerade": True,
                "state": "enabled",
                "runtime": True,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called addMasquerade")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_masquerade_disabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": True,
                "offline": True,
                "Masquerade": True,
                "state": "disabled",
                "runtime": False,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_rich_rule_enabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": False,
                "offline": True,
                "masquerade": True,
                "state": "enabled",
                "runtime": True,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called addMasquerade")

    @patch("firewall_lib.FirewallClient", new_callable=MockFirewallClient, create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_rich_rule_disabled_state(self, am_class, firewall_class):
        am_class.set_params(
            {
                "permanent": True,
                "offline": True,
                "Masquerade": True,
                "state": "disabled",
                "runtime": False,
            }
        )
        firewall_class.set_params(True)
        with self.assertRaises(MockException) as e:
            firewall_lib.main()
            self.assertEqual(str(e), "called removeMasquerade")
