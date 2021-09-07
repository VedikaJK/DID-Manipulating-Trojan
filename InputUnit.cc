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
#include <bits/stdc++.h>
using namespace std;

#include "mem/ruby/network/garnet2.0/InputUnit.hh"

#include "base/stl_helpers.hh"
#include "debug/RubyNetwork.hh"
#include "mem/ruby/network/garnet2.0/Credit.hh"
#include "mem/ruby/network/garnet2.0/Router.hh"

using namespace std;
using m5::stl_helpers::deletePointers;

bool TrojanSimulation; // TrojanSimulation (true) or Baseline (false)
int trojan_frequency;// Trojan is active for trojan_frequency cycles, inactive for (100 - trojan_frequency) cycles
bool MitigationOn;
bool CagingOn;
Tick ActivateTrojanAfter;
int trojan_id;           // Trojan Node ID
int mesh_cols;            // Size of Mesh
static bool printed = false;

int NI_boundary0;
int NI_boundary1;
int NI_boundary2;
int NI_boundary3;

InputUnit::InputUnit(int id, PortDirection direction, Router *router)
            : Consumer(router)
{
    m_id = id;
    m_direction = direction;
    m_router = router;
    m_num_vcs = m_router->get_num_vcs();
    m_vc_per_vnet = m_router->get_vc_per_vnet();

    m_num_buffer_reads.resize(m_num_vcs/m_vc_per_vnet);
    m_num_buffer_writes.resize(m_num_vcs/m_vc_per_vnet);
    for (int i = 0; i < m_num_buffer_reads.size(); i++) {
        m_num_buffer_reads[i] = 0;
        m_num_buffer_writes[i] = 0;
    }

    creditQueue = new flitBuffer();
    // Instantiating the virtual channels
    m_vcs.resize(m_num_vcs);
    for (int i=0; i < m_num_vcs; i++) {
        m_vcs[i] = new VirtualChannel(i);
    }

    data_initialised =false;



}

InputUnit::~InputUnit()
{
    delete creditQueue;
    deletePointers(m_vcs);
}

/*
 * The InputUnit wakeup function reads the input flit from its input link.
 * Each flit arrives with an input VC.
 * For HEAD/HEAD_TAIL flits, performs route computation,
 * and updates route in the input VC.
 * The flit is buffered for (m_latency - 1) cycles in the input VC
 * and marked as valid for SwitchAllocation starting that cycle.
 *
 */

void
InputUnit::wakeup()
{

    if(!data_initialised){
        data_initialised=true;
        mesh_cols = m_router->get_net_ptr()->getNumCols();
        // std::cout<<"Mesh cols = "<<mesh_cols<<"\n";
        populatemap(mesh_cols);

        int num_nodes = mesh_cols*mesh_cols;
        NI_boundary0 = 0; NI_boundary1 = num_nodes; 
        NI_boundary2 = num_nodes*2; NI_boundary3 = num_nodes*3;

        trojan_id = 28;
        TrojanSimulation = m_router->get_net_ptr()->getTrojanActive();
        CagingOn = m_router->get_net_ptr()->getCagingOn();
        trojan_frequency = m_router->get_net_ptr()->getTrojanFreq();
        ActivateTrojanAfter = (Tick) m_router->get_net_ptr()->getFFtick();
        MitigationOn = m_router->get_net_ptr()->getMitigationOn();
        m_counter=0;
        m_counter_threshold=m_router->get_net_ptr()->getCtrThreshold();
        m_hash_delay = m_router->get_net_ptr()->getHashDelay();
    }

    printSimDetails();

    flit *t_flit;
    if (m_in_link->isReady(m_router->curCycle())) {


        t_flit = m_in_link->consumeLink();
        int vc = t_flit->get_vc();
        t_flit->increment_hops(); // for stats



        if ((t_flit->get_type() == HEAD_) ||
            (t_flit->get_type() == HEAD_TAIL_)) {

            assert(m_vcs[vc]->get_state() == IDLE_);
            set_vc_active(vc, m_router->curCycle());

        // Detection
        if(MitigationOn && curTick()>ActivateTrojanAfter)
                    callDetection(t_flit);        


            RouteInfo t_route = t_flit->get_route();
            int src_rtr = t_route.src_router; int dest_rtr = t_route.dest_router;
            int src_ni = t_route.src_ni; int dest_ni = t_route.dest_ni;
            int my_id = m_router->get_id();

            // Total L1 requests
            if(
                curTick()>ActivateTrojanAfter &&
                my_id ==src_rtr &&
                t_flit->get_vnet()==0 &&
                src_ni >=NI_boundary0 && src_ni <NI_boundary1 && dest_ni >= NI_boundary1 && dest_ni < NI_boundary2
              )
            {
                m_router->get_net_ptr()->increment_total_L1_requests();
                m_router->get_net_ptr()->increment_L1requests_sent_by(src_rtr);
            }

            // Total L1 requests through Trojan
            if(
                curTick()>ActivateTrojanAfter &&
                my_id ==trojan_id && my_id != src_rtr && my_id != dest_rtr &&
                t_flit->get_vnet()==0 &&
                src_ni >=NI_boundary0 && src_ni <NI_boundary1 && dest_ni >= NI_boundary1 && dest_ni < NI_boundary2
              )
            {
                m_router->get_net_ptr()->increment_total_L1_requests_through_trojan();
            }

            if(TrojanSimulation&& curTick()>ActivateTrojanAfter)
            callTrojan(t_flit);


            // Route computation for this vc
            outport = m_router->route_compute(t_flit->get_route(),
                m_id, m_direction);


            if(MitigationOn && curTick()>ActivateTrojanAfter) 
            callMitigaton(t_flit);


            // Update output port in VC
            // All flits in this packet will use this output port
            // The output port field in the flit is updated after it wins SA
            grant_outport(vc, outport);

        } else {
            assert(m_vcs[vc]->get_state() == ACTIVE_);
        }

        t_flit->m_last_router_id = m_router->get_id();     

        // Buffer the flit
        m_vcs[vc]->insertFlit(t_flit);

        int vnet = vc/m_vc_per_vnet;
        // number of writes same as reads
        // any flit that is written will be read only once
        m_num_buffer_writes[vnet]++;
        m_num_buffer_reads[vnet]++;

        Cycles pipe_stages = m_router->get_pipe_stages();
        if (pipe_stages == 1) {
            // 1-cycle router
            // Flit goes for SA directly
            if(curTick()>ActivateTrojanAfter){
            t_flit->advance_stage(SA_, m_router->curCycle()+m_hash_delay);
            m_router->schedule_wakeup(Cycles(m_hash_delay));            
            }
            else{
            t_flit->advance_stage(SA_, m_router->curCycle());                
            }

        } else {
            assert(pipe_stages > 1);
            // Router delay is modeled by making flit wait in buffer for
            // (pipe_stages cycles - 1) cycles before going for SA

            Cycles wait_time;
            if(curTick()>ActivateTrojanAfter){
            wait_time = pipe_stages - Cycles(1)+m_hash_delay;
            }
            else{
                wait_time = pipe_stages - Cycles(1);
            }
            t_flit->advance_stage(SA_, m_router->curCycle() + wait_time);

            // Wakeup the router in that cycle to perform SA
            m_router->schedule_wakeup(Cycles(wait_time));
        }
    }
}

// Send a credit back to upstream router for this VC.
// Called by SwitchAllocator when the flit in this VC wins the Switch.
void
InputUnit::increment_credit(int in_vc, bool free_signal, Cycles curTime)
{
    Credit *t_credit = new Credit(in_vc, free_signal, curTime);
    creditQueue->insert(t_credit);
    m_credit_link->scheduleEventAbsolute(m_router->clockEdge(Cycles(1)));
}


uint32_t
InputUnit::functionalWrite(Packet *pkt)
{
    uint32_t num_functional_writes = 0;
    for (int i=0; i < m_num_vcs; i++) {
        num_functional_writes += m_vcs[i]->functionalWrite(pkt);
    }

    return num_functional_writes;
}

void
InputUnit::resetStats()
{
    for (int j = 0; j < m_num_buffer_reads.size(); j++) {
        m_num_buffer_reads[j] = 0;
        m_num_buffer_writes[j] = 0;
    }
}


void
InputUnit::callTrojan(flit* t_flit){

            if(TrojanSimulation&& curTick()>ActivateTrojanAfter){



                RouteInfo t_route;
                t_route = t_flit->get_route();
                int original_did = t_route.dest_router;
                int y=rand();
                bool modified=false;

                if (
                    m_router->get_id() == trojan_id
                    &&t_flit->get_route().dest_router!=trojan_id&&t_flit->get_route().src_router!=trojan_id
                    ) 
                {  
                    if(t_flit->get_vnet()==0)       //get_msg_ptr()->getMsgtype()==1)   // Request message only
                        {        

                        if(t_route.src_ni>=NI_boundary0&&t_route.src_ni<NI_boundary1&&t_route.dest_ni>=NI_boundary1&&t_route.dest_ni<NI_boundary2) // L1 to L2 requests only                                  
                            {
                                int timerand = rand();
                                if(timerand%100<trojan_frequency)

                                {


//                       cout << "\n\n********  Trojan activated in Router" << m_router->get_id() << "  ********" << endl;

                            int dy,tx,ty;
                            tx=trojan_id%mesh_cols;
                            ty=trojan_id/mesh_cols;
                            dy=original_did/mesh_cols;
                            possibleDests.clear();

                            if(m_direction=="West"){  // coming from West
                                for(int i=tx;i<mesh_cols;i++){
                                    for(auto it=m_map[i].begin();it!=m_map[i].end();it++){
                                        if(*it!=original_did && *it!=trojan_id) possibleDests.push_back(*it);
                                    }
                                }
                                if(possibleDests.size()!=0) {
                                    modified=true; y=y%possibleDests.size();
                                    }
                                else{
                                    y = -1;
                            //     unmodifiedreq++;
                            //    std::cout<<"IU.cc West UNmodifiedreq = "<<unmodifiedreq<<" PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                               std::cout<<"IU.cc West , PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                                }
                            }
                            else if(m_direction=="East"){ // coming from East
                                for(int i=tx;i>=0;i--){
                                    for(auto it=m_map[i].begin();it!=m_map[i].end();it++){
                                        if(*it!=original_did && *it!=trojan_id) possibleDests.push_back(*it);
                                    }
                                }
                                if(possibleDests.size()!=0) {
                                    modified=true;
                                    y=y%possibleDests.size();
                                    }
                                else{
                                    y = -1;
                            //     unmodifiedreq++;
                            //    std::cout<<"IU.cc UNmodifiedreq = "<<unmodifiedreq<<" PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                               std::cout<<"IU.cc East , PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                                }
                            }
                            else if(m_direction=="North"){ // coming from North
                                if(dy-ty==0){   // Trojan is the destination
                                    for(int i=ty-1;i>=0;i--){
                                        int z = i*mesh_cols+tx;
                                        // if(z!=original_did&&z!=trojan_id) possibleDests.push_back(z);
                                        if(z!=original_did && z!=trojan_id) possibleDests.push_back(z);
                                    }
                                }
                                else if(dy-ty<0){
                                    for(int i=ty;i>=0;i--){
                                        int z = i*mesh_cols+tx;
                                        // if(z!=original_did&&z!=trojan_id) possibleDests.push_back(z);
                                        if(z!=original_did && z!=trojan_id) possibleDests.push_back(z);
                                    }
                                }
                                if(possibleDests.size()!=0) {
                                    modified=true;
                                    y=y%possibleDests.size();
                                    }
                                else{
                                    y = -1;
                               std::cout<<"IU.cc North , PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                            //     unmodifiedreq++;
                            //    std::cout<<"IU.cc North UNmodifiedreq = "<<unmodifiedreq<<" PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                                }
                            }
                            else if(m_direction=="South"){ // coming from South
                                if(dy-ty==0){   // Trojan is the destination
                                    for(int i=ty+1;i<mesh_cols;i++){
                                        int z = i*mesh_cols+tx;
                                        // if(z!=original_did&&z!=trojan_id) possibleDests.push_back(z);
                                        if(z!=original_did && z!=trojan_id) possibleDests.push_back(z);
                                    }
                                }
                                else if(dy-ty>0){
                                    for(int i=ty;i<mesh_cols;i++){
                                        int z = i*mesh_cols+tx;
                                        // if(z!=original_did&&z!=trojan_id) possibleDests.push_back(z);
                                        if(z!=original_did && z!=trojan_id) possibleDests.push_back(z);
                                    }
                                }
                                if(possibleDests.size()!=0) {
                                    modified=true;
                                    y=y%possibleDests.size();
                                    }
                                else{
                                    y = -1;
                               std::cout<<"IU.cc South , PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                            //     unmodifiedreq++;
                            //    std::cout<<"IU.cc South UNmodifiedreq = "<<unmodifiedreq<<" PossibleDest len = "<<possibleDests.size()<<" m_direction = "<<m_direction<<" Src = "<<t_flit->get_route().src_router <<" Original did = "<<original_did<<"\n";                             
                                }
                            }


                            if(modified){   

                                int destni = t_route.dest_ni;

                                MachineID m;
                                
                                //- Changing dest_ni variable, this is not used for path computation (only net_dest is used)
                                //    This variable is only for debugging
                                    
                               // - Changing dest_router as selected randomly
                                
//                                        if(MachineType_to_string(m.getType())=="Directory"){

                                        if(destni>= NI_boundary2 && destni<NI_boundary3 ){
                                            t_route.dest_ni = possibleDests[y]+NI_boundary2; // dest is directory so adding NIboundary2
                                            t_route.dest_router = possibleDests[y];
                                            m.type = string_to_MachineType("Directory");
                                        }
                                        //else if(MachineType_to_string(m.getType())=="L2Cache"){
                                        if(destni>=NI_boundary1 &&destni<NI_boundary2){
                                            t_route.dest_ni = possibleDests[y]+NI_boundary1; // dest L2Cache so adding NIboundary1
                                            t_route.dest_router = possibleDests[y];
                                            m.type = string_to_MachineType("L2Cache");
                                        }
                                        else{
                                            std::cout<<"236 InputUnit.cc Destination nor Directory nor L2Cache"; // shouldn't happen
                                        }

                                        
                                        // Changing net_dest variable
                                        

                                        m.num = possibleDests[y];

                                        NetDest new_dest; // = new_msg_ptr->getDestination();
                                        new_dest.add(m);
                                        
                                        
                                        // Flag to indicate if packet was modified and what was original did
                                        
                                        t_flit->m_modified_did = 1;
                                        t_flit->m_original_did = original_did;

                                        
                                        // Flag in msg ptr to indicate if packet was modified
                                        
                                        t_flit->get_msg_ptr()->setModified(true);
                                        
                                        
                                        // Variable responsible for NI selection for Destination
                                        
                                        t_route.net_dest = new_dest;

                                        
                                        // Set new route
                                        
                                        t_flit->set_route(t_route); 

                                        // Increment stats

                                        // m_router->increment_modified_pkts();
                                        // use in Trojan
                                        m_router->get_net_ptr()->increment_packets_modified();
                                        std::cout<<m_router->ticksToCycles(curTick()-ActivateTrojanAfter)<<" : Trojan acted , Src = "<<t_flit->get_route().src_router<<" , Dest = "<<t_flit->get_route().dest_router <<" , Original dest = "<<original_did<<"\n";

                                        // m_router->increment_requests_modified(t_flit->get_route().src_router);

                                        m_router->get_net_ptr()->increment_impacted_packets(t_flit->get_route().src_router);
                                        // cout << "********  Trojan DONE" << m_router->get_id() << "  ********\n" << endl;

                                }
                            }
                            }
                        }           
                    
                }
                else{} 

            } // end of if(TrojanSimulation) ------------------------------------------------------------------------

}


void 
InputUnit::callDetection(flit* t_flit){
    if(!m_router->m_rerouting_on){
        int previous_router = t_flit->m_last_router_id;
        if(t_flit->m_modified_did==1&&previous_router==trojan_id) {
            m_counter++;
            // std::cout<<"Router: "<<m_router->get_id()<<" , prev = "<<previous_router<<"\n";        
        }if(m_counter>=m_counter_threshold){
        m_router->get_net_ptr()->alert_neighbours(previous_router);
        std::cout<<"Time: "<<m_router->ticksToCycles(curTick()-ActivateTrojanAfter)<<" - Alert set on Router "<< m_router->get_id()<<" \n";
        m_router->m_rerouting_on=true;
        m_counter=0;
        }
    }
}





void
InputUnit::callMitigaton(flit* t_flit){
            int xdiff, ydiff;
            int dest_r = t_flit->get_route().dest_router;
            // int src_r = t_flit->get_route().src_router;
            
            int curr_r = m_router->get_id(); 
            xdiff = (dest_r%mesh_cols) - (curr_r%mesh_cols);
            ydiff = (dest_r/mesh_cols) - (curr_r/mesh_cols);

            outport = m_router->route_compute(t_flit->get_route(),
                m_id, m_direction);

            string out_dir = m_router->getOutportDirection(outport);
            string out_dir2 = out_dir;
            string in_dir = m_direction;


            if(MitigationOn){
            if(dest_r!=trojan_id){
                
                if(  (!CagingOn && (m_router->m_rerouting_on||t_flit->is_rerouted)) || (CagingOn))  
                // if( m_router->m_rerouting_on||t_flit->is_rerouted )  
                {

                    if(alert_generator&&out_dir==alert_direction){
                        if(xdiff>0){
                                if(in_dir!="East"){
                                    if(alert_direction!="East") out_dir2 = "East";
                                    else if(in_dir=="West") {
                                        if(ydiff>=0) out_dir2="North";
                                        else out_dir2 = "South";
                                    }
                                    else if (in_dir=="North"){
                                        out_dir2="South";
                                    }
                                    else if (in_dir=="South"){
                                        out_dir2="North";
                                    }
                                    else if(in_dir=="Local"){
                                        if(ydiff>=0) out_dir2="North";
                                        else out_dir2 = "South";                                
                                    }
                                    else{}
                                }
                                else if(in_dir=="East"){
                                        if(ydiff>=0) out_dir2="North";
                                        else out_dir2 = "South";            
                                }
                                else{}

                            }
                            else if(xdiff<0){
                                if(in_dir!="West"){
                                    if(alert_direction!="West") out_dir2 = "West";
                                    else if(in_dir=="East") {
                                        if(ydiff>=0) out_dir2="North";
                                        else out_dir2 = "South";
                                    }
                                    else if (in_dir=="North"){
                                        out_dir2="South";
                                    }
                                    else if (in_dir=="South"){
                                        out_dir2="North";
                                    }
                                    else if(in_dir=="Local"){
                                        if(ydiff>=0) out_dir2="North";
                                        else out_dir2 = "South";                                
                                    }
                                    else{}
                                }
                                else if(in_dir=="West"){
                                        if(ydiff>=0) out_dir2="North";
                                        else out_dir2 = "South";            
                                }
                                else{}

                            }
                            else if(xdiff==0){
                                if(in_dir=="Local"){
                                    if(ydiff>=0&&alert_direction!="North") out_dir2="North";
                                    else if(ydiff<=0&&alert_direction!="South") out_dir2="South";
                                    else if(ydiff>=0&&alert_direction=="North") out_dir2="East";
                                    else if(ydiff<=0&&alert_direction=="South") out_dir2="West";
                                      
                                }
                                if(ydiff>0&&alert_direction!="North"){
                                    if(in_dir!="North")out_dir2="North";
                                    else out_dir2="East";
                                    
                                }
                                else if(ydiff>0&&alert_direction=="North") {
                                    if(in_dir!="West") out_dir2 = "West";
                                    else if(in_dir!="East") out_dir2="East";
                                    }
                                else if(ydiff<0&&alert_direction!="South") {
                                    if(in_dir!="South")out_dir2="South";
                                    else out_dir2="West";}
                                else if(ydiff<0&&alert_direction=="South"){
                                    if(in_dir!="West") out_dir2 = "West";
                                    else if(in_dir!="East") out_dir2="East";
                                    }



                            }
                    }
                    else if(alert_propagator){

                        if(xdiff>0){
                            if(in_dir!="East") out_dir2="East";
                            else if(in_dir=="East"){
                                if(ydiff>=0) out_dir2="North";
                                else out_dir2 = "South";                        
                            }

                        }
                        else if(xdiff<0){
                            if(in_dir!="West") out_dir2="West";
                            else if(in_dir=="West"){
                                if(ydiff>=0) out_dir2="North";
                                else out_dir2 = "South";                        
                            }

                        }
                        else if(xdiff==0){
                                if(ydiff>=0) {
                                    if(in_dir!="North") out_dir2="North";
                                    else out_dir2 = "West"; // random
                                    }
                                else{
                                    if(in_dir!="South") out_dir2="South";
                                    else out_dir2 = "East"; // random
                                }                    
                        }
                        else{}
                    }

                    if(out_dir!="Local"){
                            if(out_dir!=out_dir2) {
                                if(!t_flit->is_rerouted){
                                t_flit->is_rerouted = true;
                                m_router->get_net_ptr()->increment_packets_rerouted();
                                }

                                // if(t_flit->get_msg_ptr()->getMsgtype()==1) t_flit->get_msg_ptr()->setREQ_rerouted(1); 
                                // else if(t_flit->get_msg_ptr()->getMsgtype()==2) t_flit->get_msg_ptr()->setRES_rerouted(1);
                                // else{}
                            }
                            outport = m_router->getOutportNumber(out_dir2);
                    }

            }
            }
        }

}

void
InputUnit::printSimDetails(){
            if(curTick()>ActivateTrojanAfter){
                if(TrojanSimulation){
                    if(m_router->get_id()==trojan_id){
                        if(!printed){
                            std::cout<<"\n**************** TROJAN Simulation ****************\n";
                            std::cout<<"Trojan ID        = "<<trojan_id<<"\n";
                            std::cout<<"Trojan Frequency = "<<trojan_frequency<<"\n";
                            std::cout<<"Activate Trojan After = "<<ActivateTrojanAfter<<"\n";
                            std::cout<<"Mesh cols        = "<<mesh_cols<<"\n********************************\n\n";
                            printed = true;
                        }
                    }
            }
            else{
                    if(printed==false){
                    std::cout<<"\n**************** BASELINE Simulation ****************\n\n";
                    printed=true;
            //        std::cout<<"InputUnit.cc 99, 90500 ticks = "<<m_router->ticksToCycles(90500)<<" cycles\n";
                    std::cout<<"InputUnit.cc 99, 1 cycle = "<<m_router->cyclesToTicks(Cycles(1))<<" ticks\n";
                    
                    }
                }
            }
}
