/*
 * Copyright (c) 2008 Princeton University
 * Copyright (c) 2016 Georgia Institute of Technology
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Niket Agarwal
 *          Tushar Krishna
 */


#include "mem/ruby/network/garnet2.0/NetworkInterface.hh"

#include <cassert>
#include <cmath>
#include<queue>

#include "base/cast.hh"
#include "base/stl_helpers.hh"
#include "debug/RubyNetwork.hh"
// #include "debug/MyRuby.hh"

#include "mem/ruby/network/MessageBuffer.hh"
#include "mem/ruby/network/garnet2.0/Credit.hh"
#include "mem/ruby/network/garnet2.0/flitBuffer.hh"
#include "mem/ruby/slicc_interface/Message.hh"

using namespace std;
using m5::stl_helpers::deletePointers;


uint64_t max_times_to_retransmit =1;// INT64_MAX;

static bool printretrans=false;

static map<int,queue<MRTabEntry>> MRTable;

// static int totalRequests=0;
// static int totalResponses=0;
static int totalPackets=0;
//static int maxReq=0;

static int packetsInjectedtoProtocol=0;
static int packetsInjectedBYProtocol=0;



void printQueue(queue<MRTabEntry> q)
{
	//printing content of queue 
	while (!q.empty()){
		q.pop();
	}
	cout<<endl;
}

NetworkInterface::NetworkInterface(const Params *p)
    : ClockedObject(p), Consumer(this), m_id(p->id),
      m_virtual_networks(p->virt_nets), m_vc_per_vnet(p->vcs_per_vnet),
      m_num_vcs(m_vc_per_vnet * m_virtual_networks),
      m_deadlock_threshold(p->garnet_deadlock_threshold),
      vc_busy_counter(m_virtual_networks, 0)
{
    m_router_id = -1;
    m_vc_round_robin = 0;
    m_ni_out_vcs.resize(m_num_vcs);
    m_ni_out_vcs_enqueue_time.resize(m_num_vcs);
    outCreditQueue = new flitBuffer();

    // instantiating the NI flit buffers
    for (int i = 0; i < m_num_vcs; i++) {
        m_ni_out_vcs[i] = new flitBuffer();
        m_ni_out_vcs_enqueue_time[i] = Cycles(INFINITE_);
    }

    m_vc_allocator.resize(m_virtual_networks); // 1 allocator per vnet
    for (int i = 0; i < m_virtual_networks; i++) {
        m_vc_allocator[i] = 0;
    }

    m_stall_count.resize(m_virtual_networks);


}

void
NetworkInterface::init()
{
    for (int i = 0; i < m_num_vcs; i++) {
        m_out_vc_state.push_back(new OutVcState(i, m_net_ptr));
    }
}

NetworkInterface::~NetworkInterface()
{
    deletePointers(m_out_vc_state);
    deletePointers(m_ni_out_vcs);
    delete outCreditQueue;
    delete outFlitQueue;
}



void
NetworkInterface::addInPort(NetworkLink *in_link,
                              CreditLink *credit_link)
{
    inNetLink = in_link;
    in_link->setLinkConsumer(this);
    outCreditLink = credit_link;
    credit_link->setSourceQueue(outCreditQueue);
}

void
NetworkInterface::addOutPort(NetworkLink *out_link,
                             CreditLink *credit_link,
                             SwitchID router_id)
{
    inCreditLink = credit_link;
    credit_link->setLinkConsumer(this);

    outNetLink = out_link;
    outFlitQueue = new flitBuffer();
    out_link->setSourceQueue(outFlitQueue);

    m_router_id = router_id;
}

void
NetworkInterface::addNode(vector<MessageBuffer *>& in,
                            vector<MessageBuffer *>& out)
{
    inNode_ptr = in;
    outNode_ptr = out;

    for (auto& it : in) {
        if (it != nullptr) {
            it->setConsumer(this);
        }
    }
}

void
NetworkInterface::dequeueCallback()
{
    // An output MessageBuffer has dequeued something this cycle and there
    // is now space to enqueue a stalled message. However, we cannot wake
    // on the same cycle as the dequeue. Schedule a wake at the soonest
    // possible time (next cycle).
    scheduleEventAbsolute(clockEdge(Cycles(1)));
}

void
NetworkInterface::incrementStats(flit *t_flit)
{
    if(curTick()>(Tick)m_net_ptr->getFFtick()){

    if(!printretrans){
        if(m_net_ptr->getRetransOn()){
            std::cout<<"\n\n*********  Retransmit at "<<(Tick)m_net_ptr->getRetransTimer()<<"  ************\n\n";
        }
        else{
            std::cout<<"\n\n*********  No Retransmission  ************\n\n";
        }

        printretrans = true;
    }

    int vnet = t_flit->get_vnet();

    // Latency
    m_net_ptr->increment_received_flits(vnet);
    Cycles network_delay =
        t_flit->get_dequeue_time() - t_flit->get_enqueue_time() - Cycles(1);
    Cycles src_queueing_delay = t_flit->get_src_delay();
    Cycles dest_queueing_delay = (curCycle() - t_flit->get_dequeue_time());
    Cycles queueing_delay = src_queueing_delay + dest_queueing_delay;

    m_net_ptr->increment_flit_network_latency(network_delay, vnet);
    m_net_ptr->increment_flit_queueing_latency(queueing_delay, vnet);

    if (t_flit->get_type() == TAIL_ || t_flit->get_type() == HEAD_TAIL_) {
        m_net_ptr->increment_received_packets(vnet);
        m_net_ptr->increment_packet_network_latency(network_delay, vnet);
        m_net_ptr->increment_packet_queueing_latency(queueing_delay, vnet);

    }



    // Hops
    m_net_ptr->increment_total_hops(t_flit->get_route().hops_traversed);




    }
    
}

/*
 * The NI wakeup checks whether there are any ready messages in the protocol
 * buffer. If yes, it picks that up, flitisizes it into a number of flits and
 * puts it into an output buffer and schedules the output link. On a wakeup
 * it also checks whether there are flits in the input link. If yes, it picks
 * them up and if the flit is a tail, the NI inserts the corresponding message
 * into the protocol buffer. It also checks for credits being sent by the
 * downstream router.
 */

void
NetworkInterface::wakeup()
{
    DPRINTF(RubyNetwork, "Network Interface %d connected to router %d "
            "woke up at time: %lld\n", m_id, m_router_id, curCycle());

    MsgPtr msg_ptr;
    Tick curTime = clockEdge();
    


    // Checking for messages coming from the protocol
    // can pick up a message/cycle for each virtual net
    for (int vnet = 0; vnet < inNode_ptr.size(); ++vnet) {
        MessageBuffer *b = inNode_ptr[vnet];
        if (b == nullptr) {
            continue;
        }

        if (b->isReady(curTime)) { // Is there a message waiting

            msg_ptr = b->peekMsgPtr();

            if (flitisizeMessage(msg_ptr, vnet,false)) {
                    totalPackets++;
                    packetsInjectedBYProtocol++;
//                    std::cout<<"260 NI.cc injected by protocol = "<<packetsInjectedBYProtocol<<"\n";
//                    std::cout<<"Request Packets injected by core = "<<totalPackets<<"\n";

                b->dequeue(curTime);
            }

        }

    }

    scheduleOutputLink();
    checkReschedule();






    // Check if there are flits stalling a virtual channel. Track if a
    // message is enqueued to restrict ejection to one message per cycle.
    bool messageEnqueuedThisCycle = checkStallQueue();

    /*********** Check the incoming flit link **********/
    if (inNetLink->isReady(curCycle())) {
        flit *t_flit = inNetLink->consumeLink();
        int vnet = t_flit->get_vnet();
        t_flit->set_dequeue_time(curCycle());

        // If a tail flit is received, enqueue into the protocol buffers if
        // space is available. Otherwise, exchange non-tail flits for credits.
        if (t_flit->get_type() == TAIL_ || t_flit->get_type() == HEAD_TAIL_) {
            if (!messageEnqueuedThisCycle &&
                outNode_ptr[vnet]->areNSlotsAvailable(1, curTime)) {

                /*Add to priority queue of src ni if msg was mofified*/

                if(m_net_ptr->getRetransOn()){

                    if(t_flit->get_msg_ptr()->getModified()){

                        MRTabEntry tabentry(t_flit->get_msg_ptr(),t_flit->get_vnet(),curTick());
                        int srcni = t_flit->get_route().src_ni;
                        MRTable[srcni].push(tabentry);

                    }

                }

                // Space is available. Enqueue to protocol buffer.
                outNode_ptr[vnet]->enqueue(t_flit->get_msg_ptr(), curTime,
                                           cyclesToTicks(Cycles(1)));
                packetsInjectedtoProtocol++;
//                std::cout<<"260 NI.cc injected to protocol = "<<packetsInjectedtoProtocol<<"\n";

                // Simply send a credit back since we are not buffering
                // this flit in the NI
                sendCredit(t_flit, true);

                // Update stats and delete flit pointer
                incrementStats(t_flit);
                delete t_flit;
            } else {
                // No space available- Place tail flit in stall queue and set
                // up a callback for when protocol buffer is dequeued. Stat
                // update and flit pointer deletion will occur upon unstall.
                m_stall_queue.push_back(t_flit);
                m_stall_count[vnet]++;

                auto cb = std::bind(&NetworkInterface::dequeueCallback, this);
                outNode_ptr[vnet]->registerDequeueCallback(cb);
            }
        } else {
            // Non-tail flit. Send back a credit but not VC free signal.
            sendCredit(t_flit, false);

            // Update stats and delete flit pointer.
            incrementStats(t_flit);
            delete t_flit;
        }
    }

    /****************** Check the incoming credit link *******/

    if (inCreditLink->isReady(curCycle())) {
        Credit *t_credit = (Credit*) inCreditLink->consumeLink();
        m_out_vc_state[t_credit->get_vc()]->increment_credit();
        if (t_credit->is_free_signal()) {
            m_out_vc_state[t_credit->get_vc()]->setState(IDLE_, curCycle());
        }
        delete t_credit;
    }


    // It is possible to enqueue multiple outgoing credit flits if a message
    // was unstalled in the same cycle as a new message arrives. In this
    // case, we should schedule another wakeup to ensure the credit is sent
    // back.
    if (outCreditQueue->getSize() > 0) {
        outCreditLink->scheduleEventAbsolute(clockEdge(Cycles(1)));
    }



    if(m_net_ptr->getRetransOn()){

        if(!MRTable[m_id].empty()){

            if(MRTable[m_id].front().received_time<=curTick()){

                if(MRTable[m_id].front().msg_ptr->getNum_times_retransmitted()<max_times_to_retransmit){

                        if(curTick() - MRTable[m_id].front().received_time> (Tick)m_net_ptr->getRetransTimer()){

                            if(flitisizeMessage(MRTable[m_id].front().msg_ptr,MRTable[m_id].front().vnet,true)){
                                MRTable[m_id].pop();
                            }
                        }
                
                }
                else{
                    MRTable[m_id].pop();
                }

            }  


        }
    }
//        checkMRTQueue();
        scheduleEvent(Cycles(1));

}

void
NetworkInterface::sendCredit(flit *t_flit, bool is_free)
{
    Credit *credit_flit = new Credit(t_flit->get_vc(), is_free, curCycle());
    outCreditQueue->insert(credit_flit);
}

bool
NetworkInterface::checkStallQueue()
{
    bool messageEnqueuedThisCycle = false;
    Tick curTime = clockEdge();

    if (!m_stall_queue.empty()) {
        for (auto stallIter = m_stall_queue.begin();
             stallIter != m_stall_queue.end(); ) {
            flit *stallFlit = *stallIter;
            int vnet = stallFlit->get_vnet();

            // If we can now eject to the protocol buffer, send back credits
            if (outNode_ptr[vnet]->areNSlotsAvailable(1, curTime)) {
                outNode_ptr[vnet]->enqueue(stallFlit->get_msg_ptr(), curTime,
                                           cyclesToTicks(Cycles(1)));

                // Send back a credit with free signal now that the VC is no
                // longer stalled.
                sendCredit(stallFlit, true);

                // Update Stats
                incrementStats(stallFlit);

                // Flit can now safely be deleted and removed from stall queue
                delete stallFlit;
                m_stall_queue.erase(stallIter);
                m_stall_count[vnet]--;

                // If there are no more stalled messages for this vnet, the
                // callback on it's MessageBuffer is not needed.
                if (m_stall_count[vnet] == 0)
                    outNode_ptr[vnet]->unregisterDequeueCallback();

                messageEnqueuedThisCycle = true;
                break;
            } else {
                ++stallIter;
            }
        }
    }

    return messageEnqueuedThisCycle;
}

// Embed the protocol message into flits
bool
NetworkInterface::flitisizeMessage(MsgPtr msg_ptr, int vnet, bool isretransmission)
{
    Message *net_msg_ptr = msg_ptr.get();
    NetDest net_msg_dest = net_msg_ptr->getDestination();
    
    // gets all the destinations associated with this message.
    vector<NodeID> dest_nodes = net_msg_dest.getAllDest();

    // Number of flits is dependent on the link bandwidth available.
    // This is expressed in terms of bytes/cycle or the flit size
    int num_flits = (int) ceil((double) m_net_ptr->MessageSizeType_to_int(
        net_msg_ptr->getMessageSize())/m_net_ptr->getNiFlitSize());

    // loop to convert all multicast messages into unicast messages
//    std::cout<<"387 ni.cc ";
    //    flit* headflit;
    for (int ctr = 0; ctr < dest_nodes.size(); ctr++) {

        // this will return a free output virtual channel
        int vc = calculateVC(vnet);

        if (vc == -1) {
            return false ;
        }
        MsgPtr new_msg_ptr = msg_ptr->clone();
        NodeID destID = dest_nodes[ctr];
//        std::cout<<destID<<" ";
        // std::cout<<"368 NI.cc dest_nodes[ctr] = "<<destID<<"\n";
        // for(auto it=dest_nodes.begin();it!=dest_nodes.end();it++){
        //     std::cout<<*it<<" , ";
        // }
        // std::cout<<"\n";
        Message *new_net_msg_ptr = new_msg_ptr.get();
        if (dest_nodes.size() > 1) {
            // NEVER USED
            std::cout<<"NI.cc 375 Accessed\n";
            NetDest personal_dest;
            for (int m = 0; m < (int) MachineType_NUM; m++) {
                if ((destID >= MachineType_base_number((MachineType) m)) &&
                    destID < MachineType_base_number((MachineType) (m+1))) {
                    // calculating the NetDest associated with this destID
                    personal_dest.clear();
                    personal_dest.add((MachineID) {(MachineType) m, (destID -
                        MachineType_base_number((MachineType) m))});
                    new_net_msg_ptr->getDestination() = personal_dest;
                    break;
                }
            }
            net_msg_dest.removeNetDest(personal_dest);
            // removing the destination from the original message to reflect
            // that a message with this particular destination has been
            // flitisized and an output vc is acquired
            net_msg_ptr->getDestination().removeNetDest(personal_dest);
        }

        // Embed Route into the flits
        // NetDest format is used by the routing table
        // Custom routing algorithms just need destID

        
        RouteInfo route;
        route.vnet = vnet;
        route.net_dest = new_net_msg_ptr->getDestination();
        
        route.src_ni = m_id;
        route.src_router = m_router_id;
        route.dest_ni = destID;
        route.dest_router = m_net_ptr->get_router_id(destID);
        
//        std::cout<<"394 NI.cc : From "<< route.src_router<<" To "<<route.dest_router<<endl;

        
//        std::cout<<"Total Packets = "<<totalPackets<<endl;

            if(msg_ptr->getMsgtype()==1) 
            {
                // totalRequests++;
//                std::cout<<"Total Requests = "<<totalRequests<<endl;
            }
            else if(msg_ptr->getMsgtype()==2) {
                // totalResponses++;
//                std::cout<<"Total Responses = "<<totalResponses<<endl;
            }
            else{
                std::cout<<"388 NI.cc ERROR not request, not response\n";
            }

/*
    CODE TO COUNT NO OF REQUESTS
*/
        // if(route.src_router==0&&route.dest_router==10){
        //     if(msg_ptr->getMsgtype()==1){
        //         maxReq++;
        //         std::cout<<"408 NI.cc 0 to 10 Requests = "<<maxReq<<endl;
        //     } 
        // }

        // initialize hops_traversed to -1
        // so that the first router increments it to 0
        route.hops_traversed = -1;

        if(isretransmission){
            new_msg_ptr->setModified(false);
            new_msg_ptr->setNum_times_retransmitted(1+new_msg_ptr->getNum_times_retransmitted());
        }


        if(curTick()>(Tick)m_net_ptr->getFFtick()){

            m_net_ptr->increment_injected_packets(vnet);

        }



        bool isprinted=false;



        for (int i = 0; i < num_flits; i++) {
            m_net_ptr->increment_injected_flits(vnet);
            flit *fl = new flit(i, vc, vnet, route, num_flits, new_msg_ptr,
                curCycle());


            if(isretransmission){
                if(!isprinted){
                    isprinted = true;
//                    std::cout<<"NI.cc 529 , Addr = "<<new_msg_ptr->getaddr()<<" , No of times retransmitted = "<<new_msg_ptr->getNum_times_retransmitted()<<"\n";
                }
            }


            fl->set_src_delay(curCycle() - ticksToCycles(msg_ptr->getTime()));
            m_ni_out_vcs[vc]->insert(fl);

            // if(curTick()>(Tick)m_net_ptr->getFFtick()){
            // if(i==0)     classify_packet(fl); //headflit = fl;
            // }

        }

        m_ni_out_vcs_enqueue_time[vc] = curCycle();
        m_out_vc_state[vc]->setState(ACTIVE_, curCycle());
    }

//    classify_packet(headflit);
    return true ;
}

// Looking for a free output vc
int
NetworkInterface::calculateVC(int vnet)
{
    for (int i = 0; i < m_vc_per_vnet; i++) {
        int delta = m_vc_allocator[vnet];
        m_vc_allocator[vnet]++;
        if (m_vc_allocator[vnet] == m_vc_per_vnet)
            m_vc_allocator[vnet] = 0;

        if (m_out_vc_state[(vnet*m_vc_per_vnet) + delta]->isInState(
                    IDLE_, curCycle())) {
            vc_busy_counter[vnet] = 0;
            return ((vnet*m_vc_per_vnet) + delta);
        }
    }

    vc_busy_counter[vnet] += 1;
    panic_if(vc_busy_counter[vnet] > m_deadlock_threshold,
        "%s: Possible network deadlock in vnet: %d at time: %llu \n",
        name(), vnet, curTick());

    return -1;
}


/** This function looks at the NI buffers
 *  if some buffer has flits which are ready to traverse the link in the next
 *  cycle, and the downstream output vc associated with this flit has buffers
 *  left, the link is scheduled for the next cycle
 */

void
NetworkInterface::scheduleOutputLink()
{
    int vc = m_vc_round_robin;

    for (int i = 0; i < m_num_vcs; i++) {
        vc++;
        if (vc == m_num_vcs)
            vc = 0;

        // model buffer backpressure
        if (m_ni_out_vcs[vc]->isReady(curCycle()) &&
            m_out_vc_state[vc]->has_credit()) {

            bool is_candidate_vc = true;
            int t_vnet = get_vnet(vc);
            int vc_base = t_vnet * m_vc_per_vnet;

            if (m_net_ptr->isVNetOrdered(t_vnet)) {
                for (int vc_offset = 0; vc_offset < m_vc_per_vnet;
                     vc_offset++) {
                    int t_vc = vc_base + vc_offset;
                    if (m_ni_out_vcs[t_vc]->isReady(curCycle())) {
                        if (m_ni_out_vcs_enqueue_time[t_vc] <
                            m_ni_out_vcs_enqueue_time[vc]) {
                            is_candidate_vc = false;
                            break;
                        }
                    }
                }
            }
            if (!is_candidate_vc)
                continue;

            m_vc_round_robin = vc;

            m_out_vc_state[vc]->decrement_credit();
            // Just removing the flit
            flit *t_flit = m_ni_out_vcs[vc]->getTopFlit();
            t_flit->set_time(curCycle() + Cycles(1));
            outFlitQueue->insert(t_flit);
            // schedule the out link
            outNetLink->scheduleEventAbsolute(clockEdge(Cycles(1)));

            if (t_flit->get_type() == TAIL_ ||
               t_flit->get_type() == HEAD_TAIL_) {
                m_ni_out_vcs_enqueue_time[vc] = Cycles(INFINITE_);
            }
            return;
        }
    }
}

int
NetworkInterface::get_vnet(int vc)
{
    for (int i = 0; i < m_virtual_networks; i++) {
        if (vc >= (i*m_vc_per_vnet) && vc < ((i+1)*m_vc_per_vnet)) {
            return i;
        }
    }
    fatal("Could not determine vc");
}


// Wakeup the NI in the next cycle if there are waiting
// messages in the protocol buffer, or waiting flits in the
// output VC buffer
void
NetworkInterface::checkReschedule()
{
    for (const auto& it : inNode_ptr) {
        if (it == nullptr) {
            continue;
        }

        while (it->isReady(clockEdge())) { // Is there a message waiting
            scheduleEvent(Cycles(1));
            return;
        }
    }

    for (int vc = 0; vc < m_num_vcs; vc++) {
        if (m_ni_out_vcs[vc]->isReady(curCycle() + Cycles(1))) {
            scheduleEvent(Cycles(1));
            return;
        }
    }
}

void
NetworkInterface::checkMRTQueue()
{

    if(!MRTable[m_id].empty()){
        scheduleEvent(Cycles(1));
        return;
    }

}


void
NetworkInterface::print(std::ostream& out) const
{
    out << "[Network Interface]";
}

uint32_t
NetworkInterface::functionalWrite(Packet *pkt)
{
    uint32_t num_functional_writes = 0;
    for (unsigned int i  = 0; i < m_num_vcs; ++i) {
        num_functional_writes += m_ni_out_vcs[i]->functionalWrite(pkt);
    }

    num_functional_writes += outFlitQueue->functionalWrite(pkt);
    return num_functional_writes;
}

NetworkInterface *
GarnetNetworkInterfaceParams::create()
{
    return new NetworkInterface(this);
}

/*
void
NetworkInterface::classify_packet(flit* t_flit){

int NI_boundary0;
int NI_boundary1;
int NI_boundary2;
int NI_boundary3;
int mesh_cols = m_net_ptr->getNumCols();
int num_nodes = mesh_cols*mesh_cols;
NI_boundary0 = 0; NI_boundary1 = num_nodes; 
NI_boundary2 = num_nodes*2; NI_boundary3 = num_nodes*3;


    int msgtype = t_flit->get_msg_ptr()->getMsgtype(); // =1 for request, 2 for response
    int src = t_flit->get_route().src_ni;
    int dest = t_flit->get_route().dest_ni;
    int vnet = t_flit->get_route().vnet;

    if(vnet==2 && src>=NI_boundary0 && src<NI_boundary1 &&dest>=NI_boundary1 &&dest<NI_boundary2 ){
        // L1 to L2 Unblock
        m_net_ptr->increment_packet_types(0);
    }
    else if(msgtype==1){

        // L1 to L2 request
        if(src>=NI_boundary0 && src<NI_boundary1 &&dest>=NI_boundary1 &&dest<NI_boundary2 &&vnet!=2){
            m_net_ptr->increment_packet_types(1);
        }
        // L2 to L1 request
        else if(src>=NI_boundary1 &&src<NI_boundary2 &&dest>=NI_boundary0 &&dest<NI_boundary1){
            m_net_ptr->increment_packet_types(2);
        }
        // L2 to Directory request
        else if(src>=NI_boundary1 &&src<NI_boundary2 &&dest>=NI_boundary2&&dest<NI_boundary3){
            m_net_ptr->increment_packet_types(3);
        }
        // Directory to L2 request
        else if(src>=NI_boundary2 && src<NI_boundary3 &&dest>=NI_boundary1 &&dest<NI_boundary2){
            m_net_ptr->increment_packet_types(4);
        }
        // Others
        else{
            m_net_ptr->increment_packet_types(9);            
        }

    }
    else if(msgtype==2){

        // L1 to L2 response
        if(src<NI_boundary1 &&dest>=NI_boundary1 &&dest<NI_boundary2){
            m_net_ptr->increment_packet_types(5);
        }
        // L2 to L1 response
        else if(src>=NI_boundary1 &&src<NI_boundary2 &&dest>=NI_boundary0 && dest<NI_boundary1 ){
            m_net_ptr->increment_packet_types(6);
        }
        // L2 to Directory request
        else if(src>=NI_boundary1 &&src<NI_boundary2 &&dest>=NI_boundary2 && dest<NI_boundary3){
            m_net_ptr->increment_packet_types(7);
        }
        // Directory to L2 request
        else if(src>=NI_boundary2 &&src<NI_boundary3 &&dest>=NI_boundary1 &&dest<NI_boundary2){
            m_net_ptr->increment_packet_types(8);
        }
        // Others
        else{
            m_net_ptr->increment_packet_types(9);
        }

    }
    else{
        // increment other
        m_net_ptr->increment_packet_types(9);
    }

}
*/