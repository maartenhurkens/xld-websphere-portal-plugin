#
# Copyright 2018 XEBIALABS
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

from __future__ import with_statement
import sys
import xml.etree.ElementTree as ET
import xml.dom.minidom
from overtherepy import OverthereHostSession, StringUtils

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

    REQUEST_XML = '<request xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="PortalConfig_6.1.0.xsd">' \
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
    def new_instance_from_container(exec_context, deployed):
        if deployed.container.type == "was.Cluster" and deployed.container.portalHost:
            container = deployed.container
        else:
            container = deployed.container.cell

        print "Registering XmlAccess with settings from the following container: " + container.name

        return XmlAccess(exec_context, container.portalHost, container.wpHome, container.wpAdminUsername, container.wpAdminPassword, container.wpConfigUrl)

    @staticmethod
    def determine_war_installation_url(deployed):
        war_file = deployed.file.name
        c = deployed.container
        if c.cell.portalHost:
            war_install_location = "%s/%s/%s/%s.ear/%s" % (c.cell.wpProfileLocation, c.cell.installedAppDir, c.cellName, deployed.name, war_file)
        else:
            war_install_location = "%s/%s/%s/%s.ear/%s" % (c.cell.wasHome, c.cell.installedAppDir, c.cellName, deployed.name, war_file)
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
    def add_role_elm(access_control_elm, change_set, portlet, previous_security_levels, security_levels):
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
    def add_access_control_elm(portlet, portlet_elm, previous_portlet=None):
        security_levels = XmlAccess.consolidate_security_levels(portlet)
        previous_security_levels = XmlAccess.consolidate_security_levels(previous_portlet)
        change_set = ChangeSet.create(security_levels.keys(), previous_security_levels.keys())
        if not change_set.has_items():
            return

        access_control_elm = ET.SubElement(portlet_elm, "access-control")

        # add step up authentication level if specified
        if portlet.authLevel:
            access_control_elm.set("auth-level", portlet.authLevel)

        XmlAccess.add_role_elm(access_control_elm, change_set, portlet, previous_security_levels, security_levels)

    @staticmethod
    def add_parameter_elems(new_prefs, remove_prefs, portlet_elm):
        for pref_key, pref_val in new_prefs.items():
            param_elm = ET.SubElement(portlet_elm, "preferences", {"name": pref_key, "update": "set"})
            value_elm = ET.SubElement(param_elm, "value")
            value_elm.text = pref_val

        for pref_key in remove_prefs:
            ET.SubElement(portlet_elm, "preferences", {"name": pref_key, "update": "remove"})

    @staticmethod
    def add_unique_name_attr(portlet, portlet_elm):
        if XmlAccess.not_empty(portlet.uniqueName):
            portlet_elm.set("uniquename", portlet.uniqueName)

    @staticmethod
    def add_servlets(deployed, web_app_elm):
        for portlet_ci in deployed.portlets:
            ET.SubElement(web_app_elm, 'servlet', {'action': "update", "active": "true", "remote-cache-dynamic": "false",
                                                   "name": portlet_ci.portletName, "objectid": portlet_ci.portletName})

    @staticmethod
    def add_portlet_clones(portlet_app_elm, portlet_ci, common_items, portlet_object_ids):
        # Loop all portlet clones clones
        for portlet_clone_ci in portlet_ci.clones:
            # Give possibility to fully specify a technical clone name
            if "$cloned" in portlet_clone_ci.cloneName:
                clone_name = portlet_clone_ci.cloneName
            else:
                clone_name = portlet_ci.portletName + ".$cloned." + portlet_clone_ci.cloneName

            if portlet_clone_ci.cloneName in common_items:
                portlet_clone_ci_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "defaultlocale": portlet_clone_ci.defaultlocale, "name": clone_name, "servletref": portlet_ci.portletName, "objectid": portlet_object_ids[str(clone_name)]})
            else:
                portlet_clone_ci_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "defaultlocale": portlet_clone_ci.defaultlocale, "name": clone_name, "servletref": portlet_ci.portletName})

            for localedata_ci in portlet_clone_ci.localedata:
                # Add locale data
                localedata_elm = ET.SubElement(portlet_clone_ci_elm, 'localedata', {'locale': localedata_ci.locale})
                XmlAccess._add_text_elm(localedata_elm, 'title', localedata_ci.title)
                XmlAccess._add_text_elm(localedata_elm, 'description', localedata_ci.description)
                XmlAccess._add_text_elm(localedata_elm, 'keywords', localedata_ci.keywords)

            XmlAccess.add_unique_name_attr(portlet_clone_ci, portlet_clone_ci_elm)
            XmlAccess.add_parameter_elems(portlet_clone_ci.preferences, [], portlet_clone_ci_elm)
            XmlAccess.add_access_control_elm(portlet_clone_ci, portlet_clone_ci_elm)

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

        # First add servlets needed for possible cloning
        XmlAccess.add_servlets(deployed, web_app_elm)

        # Create the portal-app
        uid = XmlAccess.get_webmod_uid(deployed)
        portlet_app_elm = ET.SubElement(web_app_elm, 'portlet-app',
                                        {'action': "update", "active": "true", "uid": uid, "name": deployed.portalAppName})

        # Add all portlets
        for portlet_ci in deployed.portlets:
            portlet_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "name": portlet_ci.portletName})
            XmlAccess.add_unique_name_attr(portlet_ci, portlet_elm)
            XmlAccess.add_parameter_elems(portlet_ci.preferences, [], portlet_elm)
            XmlAccess.add_access_control_elm(portlet_ci, portlet_elm)

            XmlAccess.add_portlet_clones(portlet_app_elm, portlet_ci, [], [])

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

        # First add servlets needed for possible cloning
        XmlAccess.add_servlets(deployed, web_app_elm)

        uid = deployed.portalAppUid  # JSR-API
        if XmlAccess.not_empty(deployed.portalAppConcreteUid):
            uid = deployed.portalAppConcreteUid  # IBM-API
        portlet_app_elm = ET.SubElement(web_app_elm, 'portlet-app', {'action': "update", "active": "true", "objectid": portlet_object_ids['portlet_app_id'],
                                                                     "uid": uid, "name": deployed.portalAppName})
        # new portlets
        for portlet_name in change_set.new_items:
            portlet_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "name": portlet_name})

            #Find CI
            portlet_ci = [p for p in deployed.portlets if p.portletName == portlet_name][0]
            XmlAccess.add_unique_name_attr(portlet_ci, portlet_elm)
            XmlAccess.add_parameter_elems(portlet_ci.preferences, [], portlet_elm)
            XmlAccess.add_access_control_elm(portlet_ci, portlet_elm)

            XmlAccess.add_portlet_clones(portlet_app_elm, portlet_ci, [], [])

        # existing portlets
        for portlet_name in change_set.common_items:
            portlet_elm = ET.SubElement(portlet_app_elm, 'portlet', {'action': "update", "active": "true", "name": portlet_name,
                                                                     "objectid": portlet_object_ids[str(portlet_name)]})
            portlet_ci = [p for p in deployed.portlets if p.portletName == portlet_name][0]
            previous_portlet_ci = [p for p in previous_deployed.portlets if p.portletName == portlet_name][0]
            XmlAccess.add_unique_name_attr(portlet_ci, portlet_elm)
            pref_changeset = ChangeSet.create(portlet_ci.preferences.keys(), previous_portlet_ci.preferences.keys())
            XmlAccess.add_parameter_elems(portlet_ci.preferences, pref_changeset.removed_items, portlet_elm)
            XmlAccess.add_access_control_elm(portlet_ci, portlet_elm, previous_portlet_ci)

            # Create changeset
            current_clone_cis = [c.cloneName for c in portlet_ci.clones]
            previous_clone_cis = [c.cloneName for c in previous_portlet_ci.clones]
            clones_change_set = ChangeSet.create(current_clone_cis, previous_clone_cis)
            XmlAccess.add_portlet_clones(portlet_app_elm, portlet_ci, clones_change_set.common_items, portlet_object_ids)

            # Loop through all old clones, remove ones which are not there anymore
            for portlet_clone_name in clones_change_set.removed_items:
                ET.SubElement(portlet_app_elm, 'portlet', {'action': "delete", "name": portlet_ci.portletName + ".$cloned." + portlet_clone_name})

        for portlet_name in change_set.removed_items:
            ET.SubElement(portlet_app_elm, 'portlet', {'action': "delete", "objectid": portlet_object_ids[str(portlet_name)]})

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
        if XmlAccess.not_empty(xml_to_print):
            dom = xml.dom.minidom.parseString(xml_to_print)
            self.exec_context.logOutput(dom.toprettyxml(indent="  "))
        else:
            self.log("EMPTY")

    def log_with_header(self, header, body, is_xml=False):
        self.log(header)
        self.log_linebreak()
        if is_xml:
            self.log_xml(body)
        else:
            self.log(body)
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
            self.log("portlet(clone) found: " + portlet_elm.get("name") + ", objectId: " + portlet_elm.get("objectid"))

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

    def resolve_config_url(self, config_uri):
        wp_url = self.wp_url
        if config_uri and len(config_uri.strip()) > 0:
            config_uri = config_uri.strip()
            if config_uri[0] != '/':
                wp_url = wp_url + '/' + config_uri
            else:
                wp_url = wp_url + config_uri
        return wp_url

    def execute_and_log_input_output(self, xmlaccessscript, config_uri=None):
        self.log_with_header("The following xml will be used as input into XmlAccess :", xmlaccessscript, True)
        res_xml = self.execute(xmlaccessscript, config_uri)
        self.log_with_header("XML Access executed successfully. Output :", res_xml, True)
        return res_xml

    def execute(self, xmlaccessscript, config_uri=None):
        session = OverthereHostSession(self.host, stream_command_output=False, execution_context=self.exec_context)
        with session:
            request_file = session.upload_text_content_to_work_dir(xmlaccessscript, "request.xml")
            response_file = session.work_dir_file("response.xml")
            fs = session.os.fileSeparator
            executable = "%s%sbin%sxmlaccess%s" % (self.wp_home, fs, fs, session.os.scriptExtension)
            wp_url = self.resolve_config_url(config_uri)
            cmd_line = [executable, "-user", self.wp_user, "-password", self.wp_password, "-url", wp_url]
            cmd_line.extend(["-in", request_file.path, "-out", response_file.path])
            resp = session.execute(cmd_line, check_success=False)
            response_xml = ""
            if response_file.exists():
                response_xml = session.read_file(response_file.path)

            if resp.rc != 0:
                self.exec_context.logError("XML Access failed!!!")
                self.log_with_header("XML Access response:", response_xml, True)
                self.log_with_header("Standard out", StringUtils.concat(resp.stdout))
                self.log_with_header("Standard error", StringUtils.concat(resp.stderr))
                cmd_line[4] = '******'  # Password is 5th element in array
                self.log_with_header("Executed command line", StringUtils.concat(cmd_line, " "))
                sys.exit(1)
            return response_xml


