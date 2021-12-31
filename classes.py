class Packet:
	def __init__(self, t, dev, devaddr, rssis, uid, fcnt, mtype, info=""):
		self.rssis = rssis  #can be None, if unavailable
		self.dev_eui = dev
		self.dev_addr = devaddr
		self.t = t
		self.uid = uid
		self.fcnt = fcnt
		self.mtype = mtype
		self.info = info

	def __str__(self):
		return f"time: {self.t} devEUI: {self.dev_eui} devAddr: {self.dev_addr} uid: {self.uid} fcnt: {self.fcnt} info: {self.info} mtype: {self.mtype}"
	def __repr__(self):
		return self.__str__()
