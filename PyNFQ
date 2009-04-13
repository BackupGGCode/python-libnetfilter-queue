import libnetfilter_ll
import socket

#TODO:
#     change 0xffff in _set_mode method

NF_DROP, NF_ACCEPT, NF_STOLEN = libnetfilter_ll.NF_DROP, libnetfilter_ll.NF_ACCEPT, libnetfilter_ll.NF_STOLEN
NF_QUEUE, NF_REPEAT, NF_STOP = libnetfilter_ll.NF_QUEUE, libnetfilter_ll.NF_REPEAT, libnetfilter_ll.NF_STOP
NF_MAX_VERDICT = libnetfilter_ll.NF_MAX_VERDICT
 
NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET = libnetfilter_ll.NFQNL_COPY_NONE, libnetfilter_ll.NFQNL_COPY_META, libnetfilter_ll.NFQNL_COPY_PACKET


class NFQ(object):
   def __init__(self, packet_len = 65535, number_queue = 0, family = socket.AF_INET):
       self.packet_len = packet_len
       self.family = family

       self._create_queue(number_queue)
    
       s = socket.fromfd(self.queue_handler['fd'], 0, 0)

       while 1: 
           recived = s.recv(65535)
           libnetfilter_ll.handle_packet(self.__nfq_handler, recived, packet_len)
   

   def _create_queue(self, number_queue):
       """ create a queue and set mode then get fd, the queue are in self.queue """
       self._open_queue()
       self._unbind_pf()
       self._bind_pf()

       self.__c_handler = libnetfilter_ll.HANDLER(self._pyhandler)

       self.queue_handler = {}
       self.queue_handler['queue'] =  libnetfilter_ll.create_queue(self.__nfq_handler, number_queue, self.__c_handler, None)

       self.mode = NFQNL_COPY_PACKET
       
       nf = libnetfilter_ll.nfnlh(self.__nfq_handler)
       fd = libnetfilter_ll.nfq_fd(nf)
       self.queue_handler['fd'] = fd

   def _pyhandler(self, queue_handle, nfmsg, nfa, data):
       """ manage info then call run function """
       run_info = {}
       run_info['packet_hdr'] = libnetfilter_ll.get_full_msg_packet_hdr(nfa)
       run_info['payload'] = libnetfilter_ll.get_full_payload(nfa)
       self.run(run_info)

       #determine veredict

   def run(self, info):
       """ function that manage the packet """
       print info

   def _open_queue(self):
       """ call open_queue function in libnetfilter C library """
       self.__nfq_handler = libnetfilter_ll.open_queue()

   def _unbind_pf(self):
       """ call unbind_pf function in libnetfilter C library """
       libnetfilter_ll.unbind_pf(self.__nfq_handler, self.family)

   def _bind_pf(self):
       """ call bind_pf function in libnetfilter C library """
       libnetfilter_ll.bind_pf(self.__nfq_handler, self.family)

   def _set_mode (self, value):
       """ set queue mode"""
       libnetfilter_ll.set_mode(self.queue_handler['queue'], value, 0xfff)

   def _set_verdict(self):
       pass

   mode = property(fset = _set_mode)
   packet_veredict = property(fset = _set_verdict)

nfq = NFQ()
