# code reference: https://dev.to/satrobit/rate-limiting-using-the-token-bucket-algorithm-3cjh

import time

class TokenBucket:
    def __init__(self, tokens, time_unit, forward_callback, drop_callback):
        self.tokens = tokens
        self.time_unit = time_unit
        self.bucket = tokens
        self.forward_callback = forward_callback
        self.drop_callback = drop_callback
        self.last_check = time.time()

    def handle(self, packet):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        self.bucket = self.bucket + \
            time_passed * (self.time_unit / self.tokens)

        if self.bucket > self.tokens:
            self.bucket = self.tokens

        print(f'Bucket: {self.bucket}')
        if self.bucket < 1:
            self.drop_callback(packet)
        else:
            self.bucket = self.bucket - 1
            self.forward_callback(packet)

