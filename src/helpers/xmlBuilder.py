from src import consts

def serializeObject(obj):
    result = f"<{type(obj).__name__}>"
    
    for property, value in vars(obj).items():        
        if property in consts.XML_SERIALIZABLE_NAMES:
            result += f"<{property}>{value}</{property}>"
    
    result += f"</{type(obj).__name__}>"

    return result