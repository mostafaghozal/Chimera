import random,time
class TrafficPattern:
    MODE_RANDOM = 'random'
    MODE_FIXED = 'fixed'
    MODE_CUSTOM = 'custom'
    
    def __init__(self, mode=MODE_RANDOM, fixed_delay=1.0, random_min=0.4, random_max=1.5, custom_pattern=None):
   
        self.mode = mode
        self.fixed_delay = fixed_delay
        self.random_min = random_min
        self.random_max = random_max
        self.custom_pattern = custom_pattern or []
        self.custom_index = 0  # For iterating through custom_pattern
    
    def get_delay(self):
       
        if self.mode == self.MODE_FIXED:
            return self.fixed_delay
        elif self.mode == self.MODE_RANDOM:
            return random.uniform(self.random_min, self.random_max)
        elif self.mode == self.MODE_CUSTOM:
            if not self.custom_pattern:
                raise ValueError("Custom mode selected but no custom pattern provided.")
            # Cycle through the custom pattern list.
            delay = self.custom_pattern[self.custom_index]
            self.custom_index = (self.custom_index + 1) % len(self.custom_pattern)
            return delay
        else:
            raise ValueError("Invalid traffic pattern mode selected.")
    
    def sleep(self):
        """
        Sleeps for the delay determined by the current traffic pattern.
        """
        delay = self.get_delay()
        print(f"[TrafficPattern] Sleeping for {delay:.2f} seconds (mode: {self.mode}).")
        time.sleep(delay)
