"""The same synthetic pricing rules, split by responsibility."""


def delivery_fee(quantity, *, member=False, coupon=False, prepaid=False,
                 priority=False, remote=False, fragile=False):
    if quantity <= 0:
        return 0
    discount = _order_discount(quantity, member=member, coupon=coupon, prepaid=prepaid)
    surcharge = _transport_surcharge(priority=priority, remote=remote, fragile=fragile)
    return max(0, 8 - discount + surcharge)


def _order_discount(quantity, *, member, coupon, prepaid):
    discount = 0
    if quantity >= 5:
        discount += 2
    if quantity >= 10:
        discount += 2
    if member:
        discount += 2
    if coupon:
        discount += 1
    if prepaid:
        discount += 1
    return discount


def _transport_surcharge(*, priority, remote, fragile):
    surcharge = 0
    if priority:
        surcharge += 6
    if remote:
        surcharge += 4
    if fragile:
        surcharge += 3
    if priority and remote:
        surcharge += 2
    return surcharge


def parse_quantity(text):
    if not text:
        return None
    if not text.isdecimal():
        return None
    value = int(text)
    if value > 100:
        return None
    return value
