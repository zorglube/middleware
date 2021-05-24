from middlewared.alert.base import AlertClass, AlertCategory, Alert, AlertLevel, AlertSource, SimpleOneShotAlertClass

class SMBMisconfigurationAlert(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.SHARING
    level = AlertLevel.WARNING
    title = "SMB Share Misconfiguration Detected"
    text = "SMB Share \"%(name)s\" contains invalid parameter(s): \"%(params)s\""
