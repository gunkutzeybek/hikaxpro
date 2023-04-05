class SessionLoginCap:
    def __init__(self, session_id, challenge, salt, salt2, is_irreversible, iterations):
        self.session_id = session_id
        self.challenge = challenge
        self.salt = salt
        self.salt2 = salt2
        self.is_irreversible = is_irreversible
        self.iterations = iterations
