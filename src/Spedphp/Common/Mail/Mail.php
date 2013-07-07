<?php

/**
 * SpedPHP (http://www.nfephp.org/)
 *
 * @link      http://github.com/nfephp-org/spedphp for the canonical source repository
 * @copyright Copyright (c) 2008-2013 NFePHP (http://www.nfephp.org)
 * @license   http://www.gnu.org/licenses/lesser.html LGPL v3
 * @license   http://www.gnu.org/licenses/gpl.html GNU/GPL v.3
 * @package   SpedPHP
 */

namespace SpedPHP\Common\Mail;

/**
 * Classe modelo de emails
 * @author Gabriel Ribeiro <gabrielribeiro_@outlook.com.br>
 */
class Mail {
    
    protected $mail = null;
    protected $assunto = '';
    protected $corpo = '';
    
    public function __construct() {
        $this->mail = new \PHPMailer();
        $configuration = include __DIR__ . '/../../../config/mail.config.php';
        
        $this->mail->IsSMTP();
        $this->mail->Host = $configuration['mail']['smtp_options']['host'];
        $this->mail->SMTPAuth = true;
        $this->mail->Username = $configuration['mail']['smtp_options']['username'];
        $this->mail->Password = $configuration['mail']['smtp_options']['password'];
        $this->mail->Port = $configuration['mail']['smtp_options']['port'];
        $this->mail->SMTPSecure = $configuration['mail']['smtp_options']['smtp_secure'];
        
        $this->mail->From = $configuration['mail']['from'];
        $this->mail->FromName = $configuration['mail']['from_name'];
    }
    
    public function setAssunto($assunto) {
        $this->assunto = $assunto;
        return $this;
    }

    public function setCorpo($corpo) {
        $this->corpo = $corpo;
        return $this;
    }

    public function setDestinatario($email, $nome) {
        $this->mail->AddAddress($email, $nome);
        return $this;
    }
    
    public function send() {
        $this->mail->Subject = $this->assunto;
        $this->mail->Body    = $this->corpo;
        return $this->mail->send();
    }

    public function addAttachement($attachment, $filename = null) {
        if(is_null($filename)) {
            $filename = array_reverse(explode(DIRECTORY_SEPARATOR, $filename))[0];
        }
        $mail->addAttachment($attachment, $filename);
    }
    
}
