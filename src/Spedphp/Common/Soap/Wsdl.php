<?php

namespace Spedphp\Common\Soap;

use Spedphp\Common\Soap;
use Spedphp\Common\Exception;
use LSS\XML2Array;

/**
 * Esta classe trata os wsdl para comunicação com os webservices 
 *
 * @author Roberto L. Machado
 */
class Wsdl
{
    public function updateWsdl($wsdlDir, $wsFile, $privateKey, $publicKey)
    {
        //pega o conteúdo do xml com os endereços dos webservices
        $xml = file_get_contents($wsFile);
        //converte o xml em array
        $aWS = XML2Array::createArray($xml);
        //para cada UF
        foreach ($aWS['WS']['UF'] as $uf) {
            $sigla = $uf['sigla'];
            $aAmb = array('homologacao','producao');
            //para cada ambiente
            foreach ($aAmb as $amb) {
                $aService = $uf[$amb];
                if (isset($aService)) {
                    foreach ($aService as $nome => $aAtt) {
                        $url=$aAtt['@value'];
                        $metodo=$aAtt['@attributes']['method'];
                        //$versao = $aAtt['@attributes']['version'];
                        if ($url != '') {
                            $urlsefaz = $url.'?wsdl';
                            $fileName = $wsdlDir.DIRECTORY_SEPARATOR.$amb.DIRECTORY_SEPARATOR.
                                    $sigla.'_'.$metodo.'.asmx';
                            if ($wsdl = $this->downLoadWsdl($urlsefaz, $privateKey, $publicKey)) {
                                file_put_contents($fileName, $wsdl);
                                chmod($fileName, 755);
                            } else {
                                return false;
                            }//fim
                        }//fim if url
                    }//fim foreach
                }
            }
        }
        return true;
    }//fim updateWsdl
    
    /**
     * downloadWsdl
     * Baixa os arquivos wsdl necessários para a comunicação com 
     * SOAP nativo
     * @param string $url
     * @param string $privateKey
     * @param string $publicKey
     * @return type
     */
    protected function downLoadWsdl($url, $privateKey, $publicKey)
    {
        $soap = new Soap\CurlSoap($privateKey, $publicKey);
        return $soap->getWsdl($url);
    }//fim downLoadWsdl
}//fim WSDL
