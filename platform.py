from binaryninja import Architecture, Platform


__all__ = ['RenesasM16CPlatform']


class RenesasM16CPlatform(Platform):
    name = 'm16c'


arch = Architecture['m16c']
platform = RenesasM16CPlatform(arch)
platform.register('m16c')
