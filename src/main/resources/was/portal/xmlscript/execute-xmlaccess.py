#
# Copyright 2018 XEBIALABS
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

from was.portal.utils.xmlaccess import XmlAccess
from was.portal.utils.template import TemplateRenderer
from com.xebialabs.overthere.util import OverthereUtils

xmlaccess = XmlAccess.new_instance_from_container(context, deployed)

if is_file:
    req_file = deployed.file.getFile(req_xml)
    xml = OverthereUtils.read(req_file, "UTF-8")
else:
    xml = req_xml

rendered_xml = TemplateRenderer().render(xml, {'deployed': deployed})
xmlaccess.execute_and_log_input_output(rendered_xml, config_uri=deployed.configUri)
