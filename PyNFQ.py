import libnetfilter_ll as _libnetfilter_ll
import socket

#TODO:
#     change 0xffff in _set_mode method
#     Segmentation fault if not root in _set_mode
NF_DROP, NF_ACCEPT, NF_STOLEN = _libnetfilter_ll.NF_DROP, _libnetfilter_ll.NF_ACCEPT, _libnetfilter_ll.NF_STOLEN
NF_QUEUE, NF_REPEAT, NF_STOP = _libnetfilter_ll.NF_QUEUE, _libnetfilter_ll.NF_REPEAT, _libnetfilter_ll.NF_STOP
NF_MAX_VERDICT = _libnetfilter_ll.NF_MAX_VERDICT
 
NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET = _libnetfilter_ll.NFQNL_COPY_NONE, _libnetfilter_ll.NFQNL_COPY_META, _libnetfilter_ll.NFQNL_COPY_PACKET


class NFQ(object):
   def __init__(self, packet_len = 65535, number_queue = 0, family = socket.AF_INET, 
                target=None, args=(), kwargs=None):

       self.__target = target
       self.__args = args
       self.__kwargs = kwargs
       self.packet_len = packet_len
       self.family = family

       self._create_queue(number_queue)
    

   def start(self):
       self.__bootstrap()

   def __bootstrap(self):

       s = socket.fromfd(self.queue_handler['fd'], 0, 0)

       while True:
           recived = s.recv(65535)
           _libnetfilter_ll.handle_packet(self.__nfq_handler, recived, packet_len)

   def _create_queue(self, number_queue):
       """ create a queue and set mode then get fd, the queue are in self.queue """
       self._open_queue()
       self._unbind_pf()
       self._bind_pf()

       self.__c_handler = _libnetfilter_ll.HANDLER(self._pyhandler)
       self.queue_handler = {}
       self.queue_handler['queue'] =  _libnetfilter_ll.create_queue(self.__nfq_handler, number_queue, self.__c_handler, None)

       self.mode = NFQNL_COPY_PACKET
       
       nf = _libnetfilter_ll.nfnlh(self.__nfq_handler)
       fd = _libnetfilter_ll.nfq_fd(nf)
       self.queue_handler['fd'] = fd

   def _pyhandler(self, queue_handle, nfmsg, nfa, data):
       """ manage info then call run function """
       run_info = {}
       run_info['packet_hdr'] = _libnetfilter_ll.get_full_msg_packet_hdr(nfa)
       run_info['payload'] = _libnetfilter_ll.get_full_payload(nfa)
       self.__target(run_info)

       #determine veredict

   def run(self, info):
       """ function that manage the packet """

       try:           
           if self.__target:
               self.__target(*self.__args, **self.__kwargs)
       finally:
           del self.__target, self.__args, self.__kwargs

       print info

   def _open_queue(self):
       """ call open_queue function in libnetfilter C library """
       self.__nfq_handler =_libnetfilter_ll.open_queue()

   def _unbind_pf(self):
       """ call unbind_pf function in libnetfilter C library """
       _libnetfilter_ll.unbind_pf(self.__nfq_handler, self.family)

   def _bind_pf(self):
       """ call bind_pf function in libnetfilter C library """
       _libnetfilter_ll.bind_pf(self.__nfq_handler, self.family)

   def _set_mode (self, value):
       """ set queue mode"""
       _libnetfilter_ll.set_mode(self.queue_handler['queue'], value, 0xfff)

   def _set_verdict(self):
       pass

   mode = property(fset = _set_mode)
   packet_veredict = property(fset = _set_verdict)

nfq = NFQ()
nfq.start()
