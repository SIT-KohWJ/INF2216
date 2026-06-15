"""UserService - account lifecycle, SIT email domain validation on signup."""


class UserService:
    @staticmethod
    def register(email: str, password: str):
        # TODO: enforce @sit / SITstudent email domain, then bcrypt-hash pw.
        raise NotImplementedError("FR/D: user registration with domain check")
