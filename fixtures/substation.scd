<?xml version="1.0" encoding="UTF-8"?>
<!-- Synthetic SCD written by hand for the GOOSE Watch scenarios (src/scenarios.ts). No real substation.
     The scenario names came first, so each MMS domain splits as IED name + LD inst: "BAY1_" + "CTRL". -->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="goose-watch-synthetic" nameStructure="IEDName"/>
  <Communication>
    <SubNetwork name="StationBus" type="8-MMS">
      <ConnectedAP iedName="BAY1_" apName="AP1">
        <GSE ldInst="CTRL" cbName="gcbPos">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-11</P>
            <P type="APPID">0011</P>
            <P type="VLAN-ID">00A</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="BAY2_" apName="AP1">
        <GSE ldInst="PROT" cbName="gcbTrip">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-12</P>
            <P type="APPID">0012</P>
            <P type="VLAN-ID">00A</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="BB_" apName="AP1">
        <GSE ldInst="PROT" cbName="gcbBlk">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-13</P>
            <P type="APPID">0013</P>
            <P type="VLAN-ID">00A</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="BAY1_" manufacturer="synthetic" type="bay-controller">
    <AccessPoint name="AP1">
      <Server>
        <Authentication/>
        <LDevice inst="CTRL">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="dsPos">
              <FCDA ldInst="CTRL" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="CTRL" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcbPos" type="GOOSE" appID="BAY1_XCBR_POS" datSet="dsPos" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <IED name="BAY2_" manufacturer="synthetic" type="protection">
    <AccessPoint name="AP1">
      <Server>
        <Authentication/>
        <LDevice inst="PROT">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="dsTrip">
              <FCDA ldInst="PROT" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
              <FCDA ldInst="PROT" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcbTrip" type="GOOSE" appID="BAY2_PTRC_TRIP" datSet="dsTrip" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <IED name="BB_" manufacturer="synthetic" type="busbar-protection">
    <AccessPoint name="AP1">
      <Server>
        <Authentication/>
        <LDevice inst="PROT">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="dsBlk">
              <FCDA ldInst="PROT" lnClass="PIOC" lnInst="1" doName="Op" daName="general" fc="ST"/>
              <FCDA ldInst="PROT" lnClass="XSWI" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcbBlk" type="GOOSE" appID="BB_BLOCK" datSet="dsBlk" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>
