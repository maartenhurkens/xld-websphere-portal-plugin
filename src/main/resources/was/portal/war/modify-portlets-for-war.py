#
# THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
# FOR A PARTICULAR PURPOSE. THIS CODE AND INFORMATION ARE NOT SUPPORTED BY XEBIALABS.
#

from was.portal.utils.xmlaccess import XmlAccess

xmlaccess = XmlAccess.new_instance_from_container(context, deployed.container.cell)
xmlaccess.modify_portlets_for_war(deployed, previous_deployed)