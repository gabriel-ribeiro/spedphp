<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions xmlns:s="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/" xmlns:tns="http://www.portalfiscal.inf.br/nfe/wsdl/SCERecepcaoRFB" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/" xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" targetNamespace="http://www.portalfiscal.inf.br/nfe/wsdl/SCERecepcaoRFB" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:types>
    <s:schema elementFormDefault="qualified" targetNamespace="http://www.portalfiscal.inf.br/nfe/wsdl/SCERecepcaoRFB">
      <s:element name="sceDadosMsg">
        <s:complexType mixed="true">
          <s:sequence>
            <s:any />
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="sceRecepcaoDPECResult">
        <s:complexType mixed="true">
          <s:sequence>
            <s:any />
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="sceCabecMsg" type="tns:sceCabecMsg" />
      <s:complexType name="sceCabecMsg">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="1" name="versaoDados" type="s:string" />
        </s:sequence>
        <s:anyAttribute />
      </s:complexType>
    </s:schema>
  </wsdl:types>
  <wsdl:message name="sceRecepcaoDPECSoapIn">
    <wsdl:part name="sceDadosMsg" element="tns:sceDadosMsg" />
  </wsdl:message>
  <wsdl:message name="sceRecepcaoDPECSoapOut">
    <wsdl:part name="sceRecepcaoDPECResult" element="tns:sceRecepcaoDPECResult" />
  </wsdl:message>
  <wsdl:message name="sceRecepcaoDPECsceCabecMsg">
    <wsdl:part name="sceCabecMsg" element="tns:sceCabecMsg" />
  </wsdl:message>
  <wsdl:portType name="SCERecepcaoRFBSoap">
    <wsdl:operation name="sceRecepcaoDPEC">
      <wsdl:input message="tns:sceRecepcaoDPECSoapIn" />
      <wsdl:output message="tns:sceRecepcaoDPECSoapOut" />
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="SCERecepcaoRFBSoap" type="tns:SCERecepcaoRFBSoap">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http" />
    <wsdl:operation name="sceRecepcaoDPEC">
      <soap:operation soapAction="http://www.portalfiscal.inf.br/nfe/wsdl/SCERecepcaoRFB/sceRecepcaoDPEC" style="document" />
      <wsdl:input>
        <soap:body use="literal" />
        <soap:header message="tns:sceRecepcaoDPECsceCabecMsg" part="sceCabecMsg" use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal" />
        <soap:header message="tns:sceRecepcaoDPECsceCabecMsg" part="sceCabecMsg" use="literal" />
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="SCERecepcaoRFBSoap12" type="tns:SCERecepcaoRFBSoap">
    <soap12:binding transport="http://schemas.xmlsoap.org/soap/http" />
    <wsdl:operation name="sceRecepcaoDPEC">
      <soap12:operation soapAction="http://www.portalfiscal.inf.br/nfe/wsdl/SCERecepcaoRFB/sceRecepcaoDPEC" style="document" />
      <wsdl:input>
        <soap12:body use="literal" />
        <soap12:header message="tns:sceRecepcaoDPECsceCabecMsg" part="sceCabecMsg" use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal" />
        <soap12:header message="tns:sceRecepcaoDPECsceCabecMsg" part="sceCabecMsg" use="literal" />
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="SCERecepcaoRFB">
    <wsdl:port name="SCERecepcaoRFBSoap" binding="tns:SCERecepcaoRFBSoap">
      <soap:address location="https://www.nfe.fazenda.gov.br/SCERecepcaoRFB/SCERecepcaoRFB.asmx" />
    </wsdl:port>
    <wsdl:port name="SCERecepcaoRFBSoap12" binding="tns:SCERecepcaoRFBSoap12">
      <soap12:address location="https://www.nfe.fazenda.gov.br/SCERecepcaoRFB/SCERecepcaoRFB.asmx" />
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>