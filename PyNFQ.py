import os, socket
import libnetfilter_ll as _libnetfilter_ll
from libnetfilter_ll import NFQNL_COPY_NONE as MODE_NONE, NFQNL_COPY_META as MODE_META, NFQNL_COPY_PACKET as MODE_PACKET

#TODO:
#     make verify_to_change_verdict decorator
#     what is the veredicts NF_STOLEN, NF_STOP and NF_MAX_VERDICT?
#     check max_len value

class Packet(object):
   def __init__(self, buffer, buffer_len, queue, nfa):
       self.__nfa = nfa
       self.__queue = queue
       self.raw_data = buffer
       self.data_len = buffer_len
       self.nfqhdr = self._get_nfqhdr()
       self.timestamp = _libnetfilter_ll.get_pytimestamp(self.__nfa)

   def drop(self):
       self._verdict = _libnetfilter_ll.NF_DROP, None
       
   def reinject(self):
       self._verdict = _libnetfilter_ll.NF_ACCEPT, None

   def repeat(self, mark = None):
       self._verdict = _libnetfilter_ll.NF_REPEAT, mark

   def reenqueue(self, mark = None):
       self._verdict = _libnetfilter_ll.NF_QUEUE, mark
   
   def _get_nfqhdr(self):
       return _libnetfilter_ll.get_full_msg_packet_hdr(self.__nfa)


   #@verify_to_change_verdict
   def _set_verdict(self, verdict_mark):
       verdict = verdict_mark[0]
       mark = verdict_mark[1]

       if mark:
           _libnetfilter_ll.set_verdict_mark(self.__queue, self.nfqhdr['packet_id'],
                                             verdict, mark, self.data_len, self.raw_data)
       else:
           _libnetfilter_ll.set_pyverdict(self.__queue, self.nfqhdr['packet_id'],
                                          verdict, self.data_len, self.raw_data)

   def _get_mark(self):
       return _libnetfilter_ll.get_nfmark(self.__nfa)

   def _get_timestamp(self):
       _libnetfilter_ll.get_timestamp(self.__nfa)


   _verdict = property(fset = _set_verdict)
   _mark = property(fget = _get_mark)


class NFQ(object):
   def __init__(self, packet_len = 65535, number_queue = 0, family = socket.AF_INET, type = 0,
                target=None, args=(), kwargs=None):

       if kwargs is None:
           kwargs = {}  

       if os.getuid() != 0:
           raise "UserError", "You must be root"

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
       self.mode = {'mode':MODE_PACKET} #set mode and set default size data 

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

       the_mode = value.get('mode', MODE_PACKET)
       amount_data = value.get('size_data', 65535)

       _libnetfilter_ll.set_mode(self.queue_handler['queue'], the_mode, amount_data)

   def _set_max_len(self, value):
       set_queue_maxlen(self.queue_handler['queue'], value)

   mode = property(fset = _set_mode)
   max_len = property(fset = _set_max_len)

if __name__ == '__main__':
    class myNFQ(NFQ):
        def run(self, packet):
            packet.raw_data = packet.raw_data.replace('PNG','OUT')
            print 'packet changed'

            packet.reinject()


    nfq = myNFQ()
    nfq.start()
