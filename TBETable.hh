/*
 * Copyright (c) 1999-2008 Mark D. Hill and David A. Wood
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
 */

#ifndef __MEM_RUBY_STRUCTURES_TBETABLE_HH__
#define __MEM_RUBY_STRUCTURES_TBETABLE_HH__

#include <iostream>
#include<bits/stdc++.h>
#include <unordered_map>

#include "mem/ruby/common/Address.hh"

static Tick calculate_AMP_after = 1168211250; 

static bool printamp = false;

template<class ENTRY>
class TBETable
{
  public:
    TBETable(int number_of_TBEs)
        : m_number_of_TBEs(number_of_TBEs)
    {
    }

    bool isPresent(Addr address) const;
    void allocate(Addr address);
    void deallocate(Addr address);
    bool
    areNSlotsAvailable(int n, Tick current_time) const
    {
        return (m_number_of_TBEs - m_map.size()) >= n;
    }

    ENTRY *lookup(Addr address);

    // Print cache contents
    void print(std::ostream& out) const;


    void incrementpenalty(Tick x);
    Tick get_avg_misspenalty();
    int get_TBEentries_count();
    int m_coreID;
    int m_number_of_TBEs;
    Tick m_sumtotal;
    int m_cnttotal;   
    int mmax;

  private:
    // Private copy constructor and assignment operator
    TBETable(const TBETable& obj);
    TBETable& operator=(const TBETable& obj);

    // Data Members (m_prefix)
    std::unordered_map<Addr, ENTRY> m_map;

  // private:
    // int m_number_of_TBEs;
};

template<class ENTRY>
inline std::ostream&
operator<<(std::ostream& out, const TBETable<ENTRY>& obj)
{
    obj.print(out);
    out << std::flush;
    return out;
}

template<class ENTRY>
inline bool
TBETable<ENTRY>::isPresent(Addr address) const
{
    assert(address == makeLineAddress(address));
    assert(m_map.size() <= m_number_of_TBEs);
    return !!m_map.count(address);
}

template<class ENTRY>
inline void
TBETable<ENTRY>::allocate(Addr address)
{
    if(!isPresent(address)){
        assert(!isPresent(address));
        if(m_map.size() >= m_number_of_TBEs)   std::cout<<"110 TBETable.hh Assert fails \n";
        assert(m_map.size() < m_number_of_TBEs);
        m_map[address] = ENTRY();
    // print(std::cout);
        
        m_map[address].m_entry_time = curTick();
        m_map[address].m_exit_time = INT64_MAX;

    }
    else{
        std::cout<<"\n104 TBETable.hh Already present in TBE\n";
        assert(!isPresent(address));
    }
}

template<class ENTRY>
inline void
TBETable<ENTRY>::deallocate(Addr address)
{
    assert(isPresent(address));
    assert(m_map.size() > 0);
    m_map[address].m_exit_time = curTick();
    incrementpenalty(m_map[address].m_exit_time - m_map[address].m_entry_time);
    m_map.erase(address);

}

template<class ENTRY>
inline void
TBETable<ENTRY>::incrementpenalty(Tick x){

  if(curTick()>calculate_AMP_after){
    if(!printamp) {
      std::cout<<"Caclculate AMP after = "<<calculate_AMP_after<<"\n";
      printamp = true;
    }
    m_sumtotal+=x;
    m_cnttotal+=1;

  }


}


template<class ENTRY>
inline int
TBETable<ENTRY>::get_TBEentries_count(){
  return m_cnttotal;

}

template<class ENTRY>
inline Tick
TBETable<ENTRY>::get_avg_misspenalty(){


  if(m_sumtotal!=0&&m_cnttotal!=0){
    // if(flag){
    // DPRINTF(MyRuby,"Final miss penalty L1Cache Core %d - Tick = %d, Sum = %d, Cnt = %d, Avg Miss Penalty = %d\n\n", m_coreID,curTick(), m_sumtotal,m_cnttotal, m_sumtotal/m_cnttotal);
    // }

    return m_sumtotal/m_cnttotal;
  }
  else return 1;

}


// looks an address up in the cache
template<class ENTRY>
inline ENTRY*
TBETable<ENTRY>::lookup(Addr address)
{
  if (m_map.find(address) != m_map.end()) return &(m_map.find(address)->second);
  return NULL;
}


template<class ENTRY>
inline void
TBETable<ENTRY>::print(std::ostream& out) const
{
}

#endif // __MEM_RUBY_STRUCTURES_TBETABLE_HH__
