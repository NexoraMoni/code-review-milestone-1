"""Sample 3 (high complexity code smells): business logic with poor structure."""
from os.path import *

REGISTRY = []


def process_order(order, customer, coupon, region, express, gift, notes, audit, cache=[]):
    total = 0
    if order:
        for item in order["items"]:
            if item["qty"] > 0:
                if item["price"] > 0:
                    if customer["tier"] == "gold" or customer["tier"] == "platinum":
                        if coupon and coupon.startswith("X"):
                            if region == "EU" and express:
                                total += item["price"] * item["qty"] * 0.7
                            elif region == "US" and gift:
                                total += item["price"] * item["qty"] * 0.8
                            else:
                                total += item["price"] * item["qty"] * 0.9
                        else:
                            total += item["price"] * item["qty"] * 0.95
                    elif customer["tier"] == "silver":
                        total += item["price"] * item["qty"] * 0.97
                    else:
                        total += item["price"] * item["qty"]
            elif item["qty"] < 0:
                print("negative qty")
    global REGISTRY
    REGISTRY.append(total)
    cache.append(total)
    # TODO: handle currency conversion
    return total
