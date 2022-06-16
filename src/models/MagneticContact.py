from DeviceBase import DeviceBase

class MagneticContact(DeviceBase):
    def __init__(self, prop_dict):
        super().__init__(prop_dict)
        self.magnetOpenStatus = prop_dict["magnetOpenStatus"]