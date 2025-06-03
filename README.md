# 🌐 Site-LDAP-WEB

Projeto de site em **PHP** que permite aos usuários de uma rede interna (Active Directory do Windows Server) **alterar suas senhas** de forma segura via interface web.

---

## 📌 Objetivo

Facilitar a **troca de senha** pelos usuários do domínio, evitando a necessidade de intervenção do suporte técnico e permitindo maior autonomia, especialmente em ambientes com políticas de senha expirada ou mudança periódica.

---

## 🚀 Funcionalidades

- 🔐 Conexão com servidor LDAP (Active Directory)
- 👤 Autenticação do usuário com login e senha atuais
- ✅ Validação da nova senha e confirmação
- 💬 Mensagens de erro ou sucesso diretamente na interface
- 💡 Interface amigável e responsiva (HTML + CSS)

---

## 🧰 Tecnologias Utilizadas

- **PHP 8.1**
- **LDAP (Active Directory - Windows Server)**
- **HTML5**
- **CSS3**

---

## 📂 Estrutura do Projeto

```bash
Site-LDAP-WEB/
├── index.php            # Página inicial com o formulário de troca de senha
├── change_password.php  # Script que executa a alteração de senha via LDAP
├── config.php           # Configurações de conexão com o servidor LDAP
├── css/
│   └── style.css        # Estilos visuais da interface
├── img/
│   └── Logo.png         # Logo do sistema (opcional)
├── README.md            # Documentação do projeto (este arquivo)
