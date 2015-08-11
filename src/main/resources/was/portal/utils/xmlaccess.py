#
# THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
# FOR A PARTICULAR PURPOSE. THIS CODE AND INFORMATION ARE NOT SUPPORTED BY XEBIALABS.
#

from __future__ import with_statement
import sys
import xml.etree.ElementTree as ET
import xml.dom.minidom
from overtherepy import OverthereHostSession

class ChangeSet(object):

    def __init__(self, new_items, removed_items, common_items):
        self.common_items = common_items
        self.removed_items = removed_items
        self.new_items = new_items

    def has_items(self):
        return len(self.common_items) or len(self.removed_items) or len(self.new_items)

    def __str__(self):
        return "New Items %s.\nRemoved Items %s.\nCommon Items %s.\n" % (self.new_items, self.removed_items, self.common_items)

    @staticmethod
    def create(current, previous):
        current = set(current)
        previous = set(previous)
        if current is None and previous is not None:
            return ChangeSet(set(), previous, set())
        if previous is None and current is not None:
            return ChangeSet(current, set(), set())
        removed_items = previous - current
        new_items = current - previous
        common_items = previous.intersection(current)
        return ChangeSet(new_items, removed_items, common_items)


class XmlAccess(object):

    REQUEST_XML = '<request xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="PortalConfig_1.4.xsd">' \
                  '<portal action="locate"></portal></request>'

    def __init__(self, exec_context, host, wp_home, wp_user, wp_password, wp_url):
        assert host is not None, "Websphere Portal host required."
        assert XmlAccess.not_empty(wp_home), "Websphere Portal home directory required."
        assert XmlAccess.not_empty(wp_user), "Websphere Portal user required."
        assert XmlAccess.not_empty(wp_password), "Websphere Portal password required."
        assert XmlAccess.not_empty(wp_url), "Websphere Portal configuration url required."
        self.exec_context = exec_context
        self.wp_home = wp_home
        self.wp_url = wp_url
        self.wp_password = wp_password
        self.wp_user = wp_user
        self.host = host

    @staticmethod
    def new_instance_from_container(exec_context, container):
        return XmlAccess(exec_context, container.host, container.wpHome, container.wpAdminUsername, container.wpAdminPassword, container.wpConfigUrl)

    @staticmethod
    def determine_war_installation_url(deployed):
        war_file = deployed.file.name
        c = deployed.container
        war_install_location = "%s/%s/%s/%s.ear/%s" % (c.cell.wasHome, c.installedAppDir, c.cellName, deployed.name, war_file)
        war_install_location = war_install_location.replace("\\", "/")
        war_install_location = deployed.warInstallLocationPrefix + war_install_location
        return war_install_location

    @staticmethod
    def not_empty(s):
        return s is not None and len(s.strip()) > 0

    @staticmethod
    def get_webmod_uid(deployed):
        uid = "%s.webmod" % deployed.portalAppUid  # JSR-API
        if XmlAccess.not_empty(deployed.portalAppConcreteUid):
            uid = deployed.portalAppUid  # IBM-API
        return uid

    @staticmethod
    def _add_text_elm(parent, tag, text):
        elm = ET.SubElement(parent, tag)
        elm.text = text

    @staticmethod
    def consolidate_security_levels(portlet):
        security_levels = {}
        if portlet is None:
            return security_levels

        for level in portlet.securityLevels:
            group_acl = portlet.groupAclMapping.get(level)
            user_acl = portlet.userAclMapping.get(level)
            if group_acl or user_acl:
                security_levels[level] = (group_acl, user_acl)
        return security_levels

    @staticmethod
    def add_role_mapping_elm(subject_ids, previous_subject_ids, role_elm, delimiter):
        def remove_subject_mapping(change_set, subject_type):
            # remove old subject ids
            for subject_id in change_set.removed_items:
                ET.SubElement(role_elm, "mapping", {"subjectid": subject_id, "subjecttype": subject_type, "update": "remove"})

        def add_subject_mapping(change_set, subject_type):
            # add new and update subject ids
            for subject_id in (change_set.new_items | change_set.common_items):
                    ET.SubElement(role_elm, "mapping", {"subjectid": subject_id, "subjecttype": subject_type, "update": "set"})

        def split_subject_ids(sids):
            if sids is None:
                return []
            return [sid.strip() for sid in sids.split(delimiter) if sid.strip() != ""]

        group_change_set = ChangeSet.create(split_subject_ids(subject_ids[0]), split_subject_ids(previous_subject_ids[0]))
        user_change_set = ChangeSet.create(split_subject_ids(subject_ids[1]), split_subject_ids(previous_subject_ids[1]))
        remove_subject_mapping(group_change_set, "user_group")
        remove_subject_mapping(user_change_set, "user")
        add_subject_mapping(group_change_set, "user_group")
        add_subject_mapping(user_change_set, "user")

    @staticmethod
    def add_access_control_elm(portlet, portlet_elm, previous_portlet=None):
        security_levels = XmlAccess.consolidate_security_levels(portlet)
        previous_security_levels = XmlAccess.consolidate_security_levels(previous_portlet)
        change_set = ChangeSet.create(security_levels.keys(), previous_security_levels.keys())
        if not change_set.has_items():
            return

        access_control_elm = ET.SubElement(portlet_elm, "access-control")
        # unmap removed levels
        for level in change_set.removed_items:
            ET.SubElement(access_control_elm, "role", {"actionset": level, "update": "remove"})

        # add new levels
        for level in change_set.new_items:
            role_elm = ET.SubElement(access_control_elm, "role", {"actionset": level, "update": "set"})
            XmlAccess.add_role_mapping_elm(security_levels[level], ("", ""), role_elm, portlet.subjectDelimiter)

        # update existing levels
        for level in change_set.common_items:
            role_elm = ET.SubElement(access_control_elm, "role", {"actionset": level, "update": "set"})
            XmlAccess.add_role_mapping_elm(security_levels[level], previous_security_levels[level], role_elm, portlet.subjectDelimiter)

    @staticmethod
    def add_parameter_elems(new_prefs, remove_prefs, portlet_elm):
        for pref_key, pref_val in new_prefs.items():
            param_elm = ET.SubElement(portlet_elm, "parameter", {"name": pref_key, "type": "string", "update": "set"})
            param_elm.text = pref_val

        for pref_key in remove_prefs:
            ET.SubElement(portlet_elm, "parameter", {"name": pref_key, "type": "string", "update": "remove"})

    @staticmethod
    def add_unique_name_attr(portlet, portlet_elm):
        if XmlAccess.not_empty(portlet.uniqueName):
            portlet_elm.set("uniquename", portlet.uniqueName)

    @staticmethod
    def generate_register_portlets_xml(deployed, war_installation_location):
        root = ET.fromstring(XmlAccess.REQUEST_XML)
        root.set("type", "update")
        root.set("create-oids", "true")

        web_app_elm = ET.SubElement(root.find("portal"), 'web-app',
                                    {'action': "update", "active": "true", "uid": "%s.webmod" % deployed.portalAppUid, "predeployed": "true"})
        XmlAccess._add_text_elm(web_app_elm, "url", war_installation_location)
        XmlAccess._add_text_elm(web_app_elm, "context-root", deployed.contextRoot)
        XmlAccess._add_text_elm(web_app_elm, "display-name", deployed.name)

        uid = XmlAccess.get_webmod_uid(deployed)
        portlet_app_elm = ET.SubElement(web_app_elm, 'portlet-app',
                                        {'action': "update", "active": "true", "uid": uid, "name": deployed.portalAppName})

        for portlet_ci in deployed.portlets:
            portlet_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "name": portlet_ci.portletName})
            XmlAccess.add_unique_name_attr(portlet_ci, portlet_elm)
            XmlAccess.add_parameter_elems(portlet_ci.preferences, [], portlet_elm)
            XmlAccess.add_access_control_elm(portlet_ci, portlet_elm)

        return ET.tostring(root, encoding="UTF-8")

    @staticmethod
    def generate_modify_portlets_xml(deployed, previous_deployed, portlet_object_ids, change_set):
        root = ET.fromstring(XmlAccess.REQUEST_XML)
        root.set("type", "update")
        root.set("create-oids", "true")

        uid = XmlAccess.get_webmod_uid(deployed)
        web_app_elm = ET.SubElement(root.find("portal"), 'web-app',
                                    {'action': "update", "active": "true", "uid": uid, "predeployed": "true"})
        XmlAccess._add_text_elm(web_app_elm, "url", portlet_object_ids['web_app_url'])
        XmlAccess._add_text_elm(web_app_elm, "context-root", deployed.contextRoot)
        XmlAccess._add_text_elm(web_app_elm, "display-name", deployed.name)

        uid = deployed.portalAppUid  # JSR-API
        if XmlAccess.not_empty(deployed.portalAppConcreteUid):
            uid = deployed.portalAppConcreteUid  # IBM-API
        portlet_app_elm = ET.SubElement(web_app_elm, 'portlet-app', {'action': "update", "active": "true", "objectid": portlet_object_ids['portlet_app_id'],
                                                                     "uid": uid, "name": deployed.portalAppName})

        for portlet_name in change_set.new_items:
            portlet_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "name": portlet_name})
            portlet_ci = [p for p in deployed.portlets if p.portletName == portlet_name][0]
            XmlAccess.add_unique_name_attr(portlet_ci, portlet_elm)
            XmlAccess.add_parameter_elems(portlet_ci.preferences, [], portlet_elm)
            XmlAccess.add_access_control_elm(portlet_ci, portlet_elm)

        for portlet_name in change_set.common_items:
            portlet_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "name": portlet_name,
                                                                     "objectid": portlet_object_ids[str(portlet_name)]})
            portlet_ci = [p for p in deployed.portlets if p.portletName == portlet_name][0]
            previous_portlet_ci = [p for p in previous_deployed.portlets if p.portletName == portlet_name][0]
            XmlAccess.add_unique_name_attr(portlet_ci, portlet_elm)
            pref_changeset = ChangeSet.create(portlet_ci.preferences.keys(), previous_portlet_ci.preferences.keys())
            XmlAccess.add_parameter_elems(portlet_ci.preferences, pref_changeset.removed_items, portlet_elm)
            XmlAccess.add_access_control_elm(portlet_ci, portlet_elm, previous_portlet_ci)

        return ET.tostring(root, encoding="UTF-8")

    @staticmethod
    def generate_deregister_portlets_xml(deployed):
        root = ET.fromstring(XmlAccess.REQUEST_XML)
        root.set("type", "update")
        uid = XmlAccess.get_webmod_uid(deployed)
        ET.SubElement(root.find("portal"), 'web-app', {'action': "delete", "uid": uid})
        return ET.tostring(root, encoding="UTF-8")

    def log(self, msg):
        self.exec_context.logOutput(msg)

    def log_linebreak(self):
        self.exec_context.logOutput('-' * 80)

    def log_xml(self, xml_to_print):
        dom = xml.dom.minidom.parseString(xml_to_print)
        self.log_linebreak()
        self.exec_context.logOutput(dom.toprettyxml(indent="  "))
        self.log_linebreak()

    def get_portlet_object_ids(self, portal_app_uid):
        root = ET.fromstring(XmlAccess.REQUEST_XML)
        root.set("type", "export")
        ET.SubElement(root.find("portal"), 'web-app', {'action': "export", "uid": portal_app_uid})

        resp_xml = self.execute(ET.tostring(root, encoding="UTF-8"))

        root = ET.fromstring(resp_xml)
        portlet_map = {}

        for portlet_elm in root.findall(".//portlet"):
            portlet_map[portlet_elm.get("name")] = portlet_elm.get("objectid")

        portlet_map['web_app_url'] = root.find(".//url").text
        portlet_map['portlet_app_id'] = root.find(".//portlet-app").get("objectid")

        return portlet_map

    def register_portlets_for_war(self, deployed):
        self.log("Generating xmlaccess script to register portlets.")
        war_install_location = XmlAccess.determine_war_installation_url(deployed)
        req_xml = XmlAccess.generate_register_portlets_xml(deployed, war_install_location)
        self.execute_and_log_input_output(req_xml)

    def modify_portlets_for_war(self, deployed, previous_deployed):
        self.log("Calculate deltas of portlet definitions.")
        previous_portlet_cis = [p.portletName for p in previous_deployed.portlets]
        current_portlet_cis = [p.portletName for p in deployed.portlets]
        change_set = ChangeSet.create(current_portlet_cis, previous_portlet_cis)
        self.log(str(change_set))

        uid = XmlAccess.get_webmod_uid(deployed)

        self.log("Retrieve portlet configurations for webapp.")
        portlet_object_ids = self.get_portlet_object_ids(uid)

        self.log("Generating xmlaccess script to modify portlet configurations.")
        req_xml = XmlAccess.generate_modify_portlets_xml(deployed, previous_deployed, portlet_object_ids, change_set)
        self.execute_and_log_input_output(req_xml)

    def deregister_portlets_for_war(self, deployed):
        self.log("Generating xmlaccess script to undeploy portlet configurations.")
        req_xml = XmlAccess.generate_deregister_portlets_xml(deployed)
        self.execute_and_log_input_output(req_xml)

    def execute_and_log_input_output(self, xmlaccessscript):
        self.log("The following xml will be used as input into XmlAccess :")
        self.log_xml(xmlaccessscript)
        res_xml = self.execute(xmlaccessscript)
        self.log("XML Access executed successfully. Output :")
        self.log_xml(res_xml)
        return res_xml

    def execute(self, xmlaccessscript):
        session = OverthereHostSession(self.host, stream_command_output=False, execution_context=self.exec_context)
        with session:
            request_file = session.upload_text_content_to_work_dir(xmlaccessscript, "request.xml")
            response_file = session.work_dir_file("response.xml")
            fs = session.os.fileSeparator
            executable = "%s%sbin%sxmlaccess%s" % (self.wp_home, fs, fs, session.os.scriptExtension)
            cmd_line = [executable, "-user", self.wp_user, "-password", self.wp_password, "-url", self.wp_url]
            cmd_line.extend(["-in", request_file.path, "-out", response_file.path])
            resp = session.execute(cmd_line, check_success=False)
            response_xml = ""
            if response_file.exists():
                response_xml = session.read_file(response_file.path)

            if resp.rc != 0:
                self.exec_context.logError("XML Access failed!!! Output :")
                self.log_xml(response_xml)
                sys.exit(1)
            return response_xml

