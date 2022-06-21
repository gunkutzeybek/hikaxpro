from src import consts
import xml.etree.ElementTree as ET

def serializeObject(obj):
    result = f"<{type(obj).__name__}>"
    
    for property, value in vars(obj).items():        
        if property in consts.XML_SERIALIZABLE_NAMES:
            result += f"<{property}>{value}</{property}>"
    
    result += f"</{type(obj).__name__}>"

    return result

def get_mac_address_of_interface(xmlData, interface_id):
    try:
        root = ET.fromstring(xmlData)
        namespaces = {'xmlns': consts.XML_SCHEMA}        
        for ni_element in root.findall('xmlns:NetworkInterface', namespaces):
            if ni_element.find('xmlns:id', namespaces).text == str(interface_id):
                link_elm = ni_element.find('xmlns:Link', namespaces)
                return link_elm.find('xmlns:MACAddress', namespaces).text
    except(Exception) as ex:
        return ''
    
    return ''