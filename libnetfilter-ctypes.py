import ctypes
import ctypes.util as utils
import socket
import os

#TODO:
#como hago un typedef int lala, esto lo necesito para definir nfq_callback

#cargamos la libreria
netfilter = ctypes.cdll.LoadLibrary(utils.find_library('netfilter_queue'))

#declaramos los structs
class nfq_handle (ctypes.Structure):
    pass

class nfq_q_handle(ctypes.Structure):
    pass

class nfq_data(ctypes.Structure):
    pass


class nfqnl_msg_packet_hdr(ctypes.Structure):
    _fields_ = [('packet_id', ctypes.c_uint32),
                ('hw_protocol', ctypes.c_uint16),
                ('hook', ctypes.c_uint8)]

#definimos los structs
class nfnl_handle(ctypes.Structure):
    _fields_ = [('fd', ctypes.c_int),
                ('subscriptions', ctypes.c_uint32),
                ('seq', ctypes.c_uint32),
                ('dump', ctypes.c_uint32),
                ('rcv_buffer_size', ctypes.c_uint32),
                #como los proximos datos no me interesan
                #defino que van a ser void pointers
                ('local', ctypes.c_void_p),
                ('peer', ctypes.c_void_p),
                ('last_nlhdr', ctypes.c_void_p),
                ('subsys', ctypes.c_void_p)]

call = ctypes.CFUNCTYPE(
                 ctypes.c_int, *(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
        )

class nfnl_callback(ctypes.Structure):
    _fileds_ = [('call', call),
                ('data', ctypes.c_void_p),
                ('attr_count', ctypes.c_uint16)]

class nfnl_subsys_handle(ctypes.Structure):
    _fields_ = [('nfilter_handler', ctypes.POINTER(nfnl_handle)),
                ('subscriptions', ctypes.c_uint32),
                ('subsys_id', ctypes.c_uint8),
                ('cb_count', ctypes.c_uint8),
                ('callback', ctypes.POINTER(nfnl_callback))]

class nfq_handle(ctypes.Structure):
    _fields_ = [('nfnlh', ctypes.POINTER(nfnl_handle)),
                ('nfnlssh', ctypes.POINTER(nfnl_subsys_handle)),
                ('qh_list', ctypes.POINTER(nfq_q_handle))]

class nfq_q_handle( ctypes.Structure):
    _fields_ = [('next', ctypes.POINTER(nfq_q_handle)),
                ('h', ctypes.POINTER(nfq_handle)),
                ('id', ctypes.c_uint16),
                ('cb', ctypes.c_void_p),
                ('data', ctypes.c_void_p)]

class nfq_data(ctypes.Structure):
    _fields_ = [('nfilter_handler', ctypes.POINTER(nfnl_handle)),
                ('nfilter_subsys_handle', ctypes.POINTER(nfnl_subsys_handle)),
                ('netfilter_queue_handle', ctypes.POINTER(nfq_q_handle))]


class  nfqnl_msg_packet_hdr(ctypes.Structure):
    _fields_ = [('packet_id', ctypes.c_uint32),
                ('hw_protocol', ctypes.c_uint16),
                ('hook', ctypes.c_uint8)]


#if os.getuid() != 0:
#    print 'Necesitas ser root para poder utilizar esta libreria'
#    exit()


### ACA VAN TODAS LAS COSAS QUE VAN A SER PUBLICAS PARA LA LIB
### nfq tendria que ser una clase de donde se van a heredar las cosas, y lo metosdos son todos estos
### la clase nfq tiene estos metodos
#

#Definimos nuestras funciones, los valores que reciven y los que retornan
nfq_open = netfilter.nfq_open
nfq_open.restype = ctypes.POINTER(nfq_handle)
########

unbind_pf = netfilter.nfq_unbind_pf
unbind_pf.restype = ctypes.c_int
unbind_pf.argtypes = ctypes.POINTER(nfq_handle), ctypes.c_uint16
########

bind_pf = netfilter.nfq_bind_pf
bind_pf.restype = ctypes.c_int
bind_pf.argtypes = ctypes.POINTER(nfq_handle), ctypes.c_uint16 
########

create_queue = netfilter.nfq_create_queue
create_queue.restype = ctypes.POINTER(nfq_handle)
create_queue.argtypes = ctypes.POINTER(nfq_handle), ctypes.c_uint16, ctypes.c_void_p, ctypes.c_void_p
########

set_mode = netfilter.nfq_set_mode
set_mode.restype = ctypes.c_int
set_mode.argtypes = ctypes.POINTER(nfq_handle), ctypes.c_uint8, ctypes.c_uint32
########

nfnlh = netfilter.nfq_nfnlh
nfnlh.restype = ctypes.POINTER(nfnl_handle)
nfnlh.argtypes = ctypes.POINTER(nfq_handle),
########

nfq_fd = netfilter.nfnl_fd
nfq_fd.restype = ctypes.c_int
nfq_fd.argtypes = ctypes.POINTER(nfnl_handle),
########

handle_packet = netfilter.nfq_handle_packet
handle_packet.restype = ctypes.c_int
handle_packet.argtypes = ctypes.POINTER(nfq_handle), ctypes.c_char_p, ctypes.c_int
########

destroy_queue = netfilter.nfq_destroy_queue
destroy_queue.restype = ctypes.c_int
destroy_queue.argtypes = ctypes.POINTER(nfq_handle),
########

nfq_close = netfilter.nfq_close
nfq_close.restype = ctypes.c_int
nfq_close.argtypes = ctypes.POINTER(nfq_handle),
########


get_payload = netfilter.nfq_get_payload
get_payload.restype = ctypes.c_int
get_payload.argtypes = ctypes.POINTER(nfq_data), ctypes.POINTER(ctypes.c_char_p)
########

get_msg_packet_hdr = netfilter.nfq_get_msg_packet_hdr
get_msg_packet_hdr.restype = ctypes.POINTER(nfqnl_msg_packet_hdr)
get_msg_packet_hdr.argtypes = ctypes.POINTER(nfq_data),
########

set_verdict = netfilter.nfq_set_verdict
set_verdict.restype = ctypes.c_int
set_verdict.argtypes = ctypes.POINTER(nfq_q_handle), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p
########

get_physoutdev = netfilter.nfq_get_physoutdev
get_physoutdev.restype = ctypes.c_uint32
get_physoutdev.argtypes = ctypes.POINTER(nfq_data),
########

get_outdev = netfilter.nfq_get_outdev
get_outdev.restype = ctypes.c_uint32
get_outdev.argtypes = ctypes.POINTER(nfq_data),
########

get_physindev = netfilter.nfq_get_physindev
get_physindev.restype = ctypes.c_uint32
get_physindev.argtypes = ctypes.POINTER(nfq_data),
########

get_indev = netfilter.nfq_get_indev
get_indev.restype = ctypes.c_uint32
get_indev.argtypes = ctypes.POINTER(nfq_data),
########


def handler(uno, dos, tres, cuatro):
    pkg_hdr = get_msg_packet_hdr(tres)
    #como hago ahora para acceder a los atributos de pkg_hdr 
    #si se que es un int porque la funcion retorna un puntero a una estuctura

    print socket.ntohl(pkg_hdr.contents.packet_id)

    full_packet = ctypes.c_char_p(0)
   
    len_recv = get_payload(tres, ctypes.byref(full_packet));
    
    print "catidad de bytes recividos", len_recv
    print "como recivi mas de 0 bytes, los datos los tengo que ver con el modulo struct o con impacket," "esto lo veo LUEGO" #dir(full_packet)

    print "get_phyindev", get_physindev(tres)
    NF_ACCEPT = 1
    set_verdict(uno, socket.ntohl(pkg_hdr.contents.packet_id), NF_ACCEPT, len_recv, full_packet)

    #tiene que retornar si o si un entero porque el HANDLER DICE QUE TIENE QUE RETORNALO
    return 0


HANDLER = ctypes.CFUNCTYPE(
                           #(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
                           ctypes.c_int, *(ctypes.POINTER(nfq_q_handle), ctypes.c_void_p, ctypes.POINTER(nfq_data), ctypes.c_void_p)
        )

c_handler = HANDLER(handler)

nfqh = nfq_open()

unbind_pf(nfqh, socket.AF_INET)
bind_pf(nfqh, socket.AF_INET)
queue = create_queue(nfqh, 0, c_handler, None)

#NO HAY QUE HARDCODEAR ESTOS DATOS
set_mode(queue, 2, 0xffff)
#################################

nf = nfnlh(nfqh)
fd = nfq_fd(nf)


#ESTO ES MUYYYY FEOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
s = socket.fromfd(fd, 0, 0)
while 1:
    recivido = s.recv(65535)
    handle_packet(nfqh, recivido, 65535)
##################################################

destroy_queue(queue)
nfq_close(nfqh)


#struct nfq_handle *nfq_open_nfnl(struct nfnl_handle *nfnlh)
#int nfq_set_queue_maxlen(struct nfq_q_handle *qh, u_int32_t queuelen)
#static struct nfq_q_handle *find_qh(struct nfq_handle *h, u_int16_t id)
#static void add_qh(struct nfq_q_handle *qh)
#static void del_qh(struct nfq_q_handle *qh)
#struct nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(struct nfq_data *nfad)
####nfq_get_payload
##uint32_t nfq_get_nfmark(struct nfq_data *nfad)
##int nfq_get_timestamp(struct nfq_data *nfad, struct timeval *tv)
#struct nfqnl_msg_packet_hw *nfq_get_packet_hw(struct nfq_data *nfad)
#int nfq_set_verdict_mark(struct nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t mark, u_int32_t datalen, unsigned char *buf)
