class ReleaseWorkflowError(ValueError):
    pass


class GitIdentityError(ReleaseWorkflowError):
    pass


class ContentManifestError(ReleaseWorkflowError):
    pass


class ContentMismatchError(ContentManifestError):
    pass


class ShadowVerificationError(ReleaseWorkflowError):
    pass
