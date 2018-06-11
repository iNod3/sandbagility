class Breakpoint():

    def update_breakpoint(self, BID, handler, cr3):

        self.breakpoints[cr3]['id'] = BID

        if handler not in self.breakpoints[cr3]['handler']:
            self.breakpoints[cr3]['handler'].append(handler)

        return BID

    def add_breakpoint(self, BID, handler, cr3):
        self.breakpoints[cr3] = {'id': BID, 'handler': [handler]}
        return BID

    def delete_breakpoint(self, cr3, handler=None):

        item = self.breakpoints[cr3]
        if item is None: return None

        if handler is None:
            if handler not in item['handler']: return item['id']
            else: item['handler'].remove(handler)

        if handler is not None:
            if handler in item['handler']:
                index = item['handler'].index(handler)
                item['handler'].pop(index)

        if len(item['handler']) == 0:
            self.breakpoints.pop(cr3)
            return item['id']

        return None

    def is_empty(self):
        return len(self.breakpoints) == 0

    def get_ID(self, cr3):
        return self.breakpoints[cr3]['id']

    def exists(self, cr3):
        return cr3 in self.breakpoints

    def get_cr3_by_ID(self, ID):
        for cr3 in self.breakpoints:
            if self.breakpoints[cr3]['id'] == ID:
                return cr3
        return None

    def get_handler(self, cr3):
        return self.breakpoints[cr3]['handler']

    def set_handler(self, cr3, handler):
        return self.breakpoints[cr3]['handler'].append(handler)

    def __init__(self, address, BID, handler, cr3, description=''):
        self.breakpoints = {}
        self.breakpoints[cr3] = {'id': BID, 'handler': [handler]}
        self.address = address
        self.description = description
