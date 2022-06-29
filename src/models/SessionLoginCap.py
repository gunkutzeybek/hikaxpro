class SessionLoginCap:
    def __init__(self, sessionID, challange, salt, salt2, isIrreversible, iterations):
        self.sessionID = sessionID
        self.challange = challange
        self.salt = salt
        self.salt2 = salt2
        self.isIrreversible = isIrreversible
        self.iteration = iterations