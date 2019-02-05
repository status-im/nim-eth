import
  karax/[karaxdsl, vdom]

import
  chronicles_tail/jsplugins

proc networkSectionContent: VNode =
  result = buildHtml(tdiv):
    text "Networking"

addSection("Network", networkSectionContent)

