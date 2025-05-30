# 🌐 Site-LDAP-WEB

Projeto de site em PHP que permite aos usuários de uma rede interna (Active Directory do Windows Server) **alterar suas senhas** de forma segura via interface web.

## 📌 Objetivo

Facilitar a **troca de senha** pelos usuários do domínio, evitando a necessidade de intervenção do suporte técnico e permitindo maior autonomia, especialmente em ambientes com políticas de senha expirada ou mudança periódica.

---

## 🚀 Funcionalidades

- Conexão com servidor LDAP (Active Directory)
- Autenticação do usuário com login e senha atuais
- Validação de nova senha com confirmação
- Interface amigável em HTML + CSS
- Feedback de erro ou sucesso

---

## 🧰 Tecnologias Utilizadas

- **PHP 8.1**
- **LDAP (Active Directory - Windows Server)**
- HTML5
- CSS3

---

## 📂 Estrutura do Projeto

```bash
Site-LDAP-WEB/
├── index.php          # Página inicial com formulário de troca de senha
├── config.php         # Configurações de conexão LDAP
├── functions.php      # Funções auxiliares (ex: conexão, validação)
├──css
    ├──style.css       # Estilos visuais
├──img
  ├──Logo.png          # Logo se quiser  
├──js
  ├── script.js        # Complementação do site
├── README.md          # Este arquivo
