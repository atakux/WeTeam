class User:

    def __init__(self, first, last):
        self.first = first
        self.last = last
    
    @property
    def email(self):
        return '{}.{}@email.com'.format(self.first, self.last)

    @property
    def fullname(self):
        return '{} {}'.format(self.first, self.last)