from binaryninja import Architecture, Platform


__all__ = ['Breach']


class BreachPlatform(Platform):
    name = 'Breach'


arch = Architecture['Breach']

breach = BreachPlatform(arch)
breach.default_calling_convention = arch.calling_conventions['default']
breach.register('breach')