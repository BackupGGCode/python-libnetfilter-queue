import os, socket
import libnetfilter_ll as _libnetfilter_ll
from impacket import ImpactDecoder
from libnetfilter_ll import NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET 

#TODO:
#     make verify_to_change_verdict decorator
#     what is the veredicts NF_STOLEN, NF_STOP and NF_MAX_VERDICT?

class Packet(object):
   def __init__(self, buffer, buffer_len, queue, nfa):
       self.__data = buffer
       self.__data_len = buffer_len
       self.__queue = queue
       self.__nfa = nfa

   def drop(self):
       self._verdict = _libnetfilter_ll.NF_DROP
       
   def reinject(self):
       self._verdict = _libnetfilter_ll.NF_ACCEPT

   def repeat(self):
       self._verdict = _libnetfilter_ll.NF_REPEAT

   def reenqueue(self):
       self._verdict = _libnetfilter_ll.NF_QUEUE
   
   def _get_nfqhdr(self):
       return _libnetfilter_ll.get_full_msg_packet_hdr(self.__nfa)

   #@verify_to_change_verdict
   def _set_verdict(self, verdict):
       _libnetfilter_ll.set_pyverdict(self.__queue, self.nfqhdr['packet_id'], 
                                      verdict, self.__data_len, self.__data) 

   
   _verdict = property(fset = _set_verdict)
   nfqhdr = property(fget = _get_nfqhdr)
#  iphdr = property(fget = _get_iphdr, fset = _set_iphdr)
#  tcphdr = property(fget = _get_tcphdr, fset = _set_tcphdr)
#  udphdr = property(fget = _get_udphdr, fset = _set_udphdr)
#  icmphdr = property(fget = _get_icmphdr, fset = _set_icmphdr)
#  payload = property(fget = _get_payload, fset = _set_payload)


class NFQ(object):
   def __init__(self, packet_len = 65535, number_queue = 0, family = socket.AF_INET, type = 0,
                target=None, args=(), kwargs=None):

       if kwargs is None:
           kwargs = {}  

       if os.getuid() != 0:
           raise "UserError", "please, get root to run this"

       self.__target = target
       self.__args = args     #args to target function
       self.__kwargs = kwargs #kwargs to target function
       self.__packet_len = packet_len 
       self.__sock_family = family
       self.__sock_type = type
        

       self._create_queue(number_queue)
    
   def _create_queue(self, number_queue):
       """ create a queue and set mode, then get fd. the queue are in self.queue """

       self._open_queue()
       self._unbind_pf()
       self._bind_pf()

       self.__c_handler = _libnetfilter_ll.HANDLER(self._pyhandler) #set python handler

       self.queue_handler = {}
       self.queue_handler['queue'] =  _libnetfilter_ll.create_queue(self.__nfq_handler, number_queue, self.__c_handler, None)
       self.mode = {'mode':NFQNL_COPY_PACKET} #set mode and set default size data 

       nf = _libnetfilter_ll.nfnlh(self.__nfq_handler)
       fd = _libnetfilter_ll.nfq_fd(nf)
       self.queue_handler['fd'] = fd

   def start(self):
       self.__bootstrap()

   def __bootstrap(self):

       s = socket.fromfd(self.queue_handler['fd'], self.__sock_family, self.__sock_type)

       while True:
           recived = s.recv(self.__packet_len)
           _libnetfilter_ll.handle_packet(self.__nfq_handler, recived, self.__packet_len)


   def _pyhandler(self, queue_handle, nfmsg, data_queue, data):
       """ Manage info, then call run function. This method make a Packet instance, then call
           the setted target or run function and put the instance inside his param"""

       len_payload, payload = _libnetfilter_ll.get_full_payload(data_queue)
       packet_recived = Packet(payload, len_payload, self.queue_handler['queue'], data_queue)
       self.run(packet_recived)


   def run(self, info):
       """ function that manage the packet, the parameter is a Packet instance """
       try:
           self.__target(info, *self.__args, **self.__kwargs)
       except TypeError:
           raise "UnknownHandler", "packet handler is not set"

   def _open_queue(self):
       """ call open_queue function in libnetfilter C library """
       self.__nfq_handler =_libnetfilter_ll.open_queue()

   def _unbind_pf(self):
       """ call unbind_pf function in libnetfilter C library """
       _libnetfilter_ll.unbind_pf(self.__nfq_handler, self.__sock_family)

   def _bind_pf(self):
       """ call bind_pf function in libnetfilter C library """
       _libnetfilter_ll.bind_pf(self.__nfq_handler, self.__sock_family)

   def _set_mode (self, value):
       """ set queue mode"""

       the_mode = value.get('mode', NFQNL_COPY_PACKET)
       amount_data = value.get('size_data', 65535)

       _libnetfilter_ll.set_mode(self.queue_handler['queue'], the_mode, amount_data)

   mode = property(fset = _set_mode)

if __name__ == '__main__':
    class myNFQ(NFQ):
        num = 0
        def run(self, packet):
            print 'packete numero', self.num
            packet.reinject()
            del packet
            self.num += 1


    nfq = myNFQ()
    nfq.start()
