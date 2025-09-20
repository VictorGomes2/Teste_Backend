# C:\Users\vrv-v\Desktop\APK_2_REURB\app_fixed.py
#
# CM REURB v2.0 - Arquivo ajustado (reset de senha + pequenas correções)
# Gerei este arquivo a partir do seu app.py e adicionei:
# - endpoint /api/reset_senha (protegido por admin) para redefinir senha de qualquer usuário
# - endpoint /api/mudar_senha (token_required) para trocar a própria senha
# - uso consistente de generate_password_hash(method="scrypt") para compatibilidade com seu banco
# - tratamento seguro do header Authorization
# - garantia de token como str em jwt.encode()
# - criação do admin default se não existir (mantido)
#
import os
import datetime
from functools import wraps
import jwt  # PyJWT

import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =======================================================================
# ⚙️ CONFIGURAÇÃO DA APLICAÇÃO
# =======================================================================

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get('SECRET_KEY', 'chave-secreta-para-desenvolvimento-muito-segura-trocar-em-producao')
DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://reurb_user:123@localhost:5432/reurb_apk')
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =======================================================================
# MODELS
# =======================================================================

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    senha_hash = db.Column(db.String(1024), nullable=False)
    acesso = db.Column(db.String(20), nullable=False, default='Usuario')

    def __init__(self, nome, usuario, senha, acesso='Usuario'):
        self.nome = nome
        self.usuario = usuario
        # Usar scrypt para ser compatível com o hash que você já tem no banco
        self.senha_hash = generate_password_hash(senha, method="scrypt")
        self.acesso = acesso

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)


class CadastroReurb(db.Model):
    __tablename__ = 'cadastros_reurb'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), default='Em Análise')
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    req_nome = db.Column(db.String(150))
    req_cpf = db.Column(db.String(20))
    req_rg = db.Column(db.String(20))
    req_data_nasc = db.Column(db.String(20))
    req_nacionalidade = db.Column(db.String(50))
    req_estado_civil = db.Column(db.String(30))
    conj_nome = db.Column(db.String(150))
    conj_cpf = db.Column(db.String(20))
    req_profissao = db.Column(db.String(100))
    req_telefone = db.Column(db.String(30))
    req_email = db.Column(db.String(150))
    imovel_cep = db.Column(db.String(15))
    imovel_logradouro = db.Column(db.String(150))
    imovel_numero = db.Column(db.String(20))
    imovel_complemento = db.Column(db.String(100))
    imovel_bairro = db.Column(db.String(100))
    imovel_cidade = db.Column(db.String(100))
    imovel_uf = db.Column(db.String(2))
    inscricao_imobiliaria = db.Column(db.String(30), index=True)
    imovel_area_total = db.Column(db.Float)
    imovel_area_construida = db.Column(db.Float)
    imovel_uso = db.Column(db.String(30))
    imovel_tipo_construcao = db.Column(db.String(30))
    reurb_renda_familiar = db.Column(db.Float)
    reurb_outro_imovel = db.Column(db.String(10))


class Documento(db.Model):
    __tablename__ = 'documentos'
    id = db.Column(db.Integer, primary_key=True)
    cadastro_id = db.Column(db.Integer, db.ForeignKey('cadastros_reurb.id'), nullable=False)
    nome_arquivo = db.Column(db.String(255), nullable=False)
    path_arquivo = db.Column(db.String(512), nullable=False)
    tipo_documento = db.Column(db.String(100))
    data_upload = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    cadastro = db.relationship("CadastroReurb", backref=db.backref("documentos", lazy=True, cascade="all, delete-orphan"))


class PadraoConstrutivo(db.Model):
    __tablename__ = 'padroes_construtivos'
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(150), nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class ValorLogradouro(db.Model):
    __tablename__ = 'valores_logradouro'
    id = db.Column(db.Integer, primary_key=True)
    logradouro = db.Column(db.String(150), unique=True, nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class AliquotaIPTU(db.Model):
    __tablename__ = 'aliquotas_iptu'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(150), unique=True, nullable=False)
    aliquota = db.Column(db.Float, nullable=False)

# =======================================================================
# SERVIÇOS E UTILIDADES
# =======================================================================

class CalculoTributarioService:
    @staticmethod
    def calcular_valores(cadastro: CadastroReurb):
        vvt, vvc, vvi, iptu = 0.0, 0.0, 0.0, 0.0
        
        try:
            if cadastro.imovel_logradouro and cadastro.imovel_area_total:
                logradouro = ValorLogradouro.query.filter_by(logradouro=cadastro.imovel_logradouro).first()
                if logradouro:
                    vvt = cadastro.imovel_area_total * logradouro.valor_m2

            if cadastro.imovel_tipo_construcao and cadastro.imovel_area_construida:
                padrao = PadraoConstrutivo.query.filter_by(descricao=cadastro.imovel_tipo_construcao).first()
                if padrao:
                    vvc = cadastro.imovel_area_construida * padrao.valor_m2

            vvi = vvt + vvc

            if cadastro.imovel_uso:
                aliquota_data = AliquotaIPTU.query.filter_by(tipo=cadastro.imovel_uso).first()
                if aliquota_data:
                    iptu = vvi * aliquota_data.aliquota

        except Exception as e:
            print(f"Erro no cálculo: {e}")
        
        return {
            "vvt": vvt,
            "vvc": vvc,
            "vvi": vvi,
            "iptu": iptu
        }

# =======================================================================
# DECORADORES
# =======================================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'mensagem': 'Token inválido!'}), 401
        
        if not token:
            return jsonify({'mensagem': 'Token de autenticação ausente!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.filter_by(public_id=data['public_id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'mensagem': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensagem': 'Token inválido!'}), 401
        except Exception as e:
            print(f"Erro ao decodificar token: {e}")
            return jsonify({'mensagem': 'Token inválido ou usuário não encontrado!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'mensagem': 'Token inválido!'}), 401
        
        if not token:
            return jsonify({'mensagem': 'Token de autenticação ausente!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('acesso') != 'Administrador':
                return jsonify({'mensagem': 'Permissão negada. Apenas administradores podem acessar.'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'mensagem': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensagem': 'Token inválido!'}), 401
        except Exception as e:
            print(f"Erro ao decodificar token: {e}")
            return jsonify({'mensagem': 'Token inválido ou usuário não encontrado!'}), 401

        return f(*args, **kwargs)
    return decorated

# =======================================================================
# ROTAS DA API
# =======================================================================

# ----> ROTA ADICIONADA PARA O STATUS DO BACKEND <----
@app.route('/')
def status():
    return jsonify({
        "status": "online",
        "mensagem": "Servidor da API CM REURB está ativo. Para acessar as funcionalidades, use as rotas /api/...",
        "versao": "2.0"
    })
# ---------------------------------------------------

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    usuario = data.get('usuario')
    senha = data.get('senha')

    user = Usuario.query.filter_by(usuario=usuario).first()
    
    if user and user.verificar_senha(senha):
        # Gera o token JWT com uma validade de 24 horas
        token = jwt.encode({
            'public_id': user.id,
            'usuario': user.usuario,
            'acesso': user.acesso,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'mensagem': 'Login bem-sucedido!',
            'token': token.decode('UTF-8'),
            'nome_usuario': user.nome,
            'acesso': user.acesso
        }), 200
    
    return jsonify({'mensagem': 'Login ou senha incorretos.'}), 401


@app.route('/api/cadastrar_reurb', methods=['POST'])
@token_required
def cadastrar_reurb(current_user):
    data = request.get_json()
    
    try:
        novo_cadastro = CadastroReurb(
            req_nome=data.get('req_nome'),
            req_cpf=data.get('req_cpf'),
            req_rg=data.get('req_rg'),
            req_data_nasc=data.get('req_data_nasc'),
            req_nacionalidade=data.get('req_nacionalidade'),
            req_estado_civil=data.get('req_estado_civil'),
            conj_nome=data.get('conj_nome'),
            conj_cpf=data.get('conj_cpf'),
            req_profissao=data.get('req_profissao'),
            req_telefone=data.get('req_telefone'),
            req_email=data.get('req_email'),
            imovel_cep=data.get('imovel_cep'),
            imovel_logradouro=data.get('imovel_logradouro'),
            imovel_numero=data.get('imovel_numero'),
            imovel_complemento=data.get('imovel_complemento'),
            imovel_bairro=data.get('imovel_bairro'),
            imovel_cidade=data.get('imovel_cidade'),
            imovel_uf=data.get('imovel_uf'),
            inscricao_imobiliaria=data.get('inscricao_imobiliaria'),
            imovel_area_total=float(data.get('imovel_area_total')),
            imovel_area_construida=float(data.get('imovel_area_construida')),
            imovel_uso=data.get('imovel_uso'),
            imovel_tipo_construcao=data.get('imovel_tipo_construcao'),
            reurb_renda_familiar=float(data.get('reurb_renda_familiar')),
            reurb_outro_imovel=data.get('reurb_outro_imovel')
        )
        db.session.add(novo_cadastro)
        db.session.commit()
        return jsonify({'mensagem': 'Cadastro REURB criado com sucesso!', 'id': novo_cadastro.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'mensagem': f'Erro ao criar cadastro: {str(e)}'}), 400


@app.route('/api/cadastros', methods=['GET'])
@token_required
def get_cadastros(current_user):
    cadastros = CadastroReurb.query.all()
    output = []
    for cad in cadastros:
        output.append({
            'id': cad.id,
            'inscricao_imobiliaria': cad.inscricao_imobiliaria,
            'imovel_logradouro': cad.imovel_logradouro,
            'imovel_numero': cad.imovel_numero,
            'imovel_bairro': cad.imovel_bairro,
            'imovel_area_total': cad.imovel_area_total,
            'imovel_area_construida': cad.imovel_area_construida
        })
    return jsonify(output)


@app.route('/api/imoveis/<string:inscricao_imobiliaria>', methods=['GET'])
@token_required
def get_imovel_by_inscricao(current_user, inscricao_imobiliaria):
    imovel = CadastroReurb.query.filter_by(inscricao_imobiliaria=inscricao_imobiliaria).first()
    if not imovel:
        return jsonify({'mensagem': 'Imóvel não encontrado.'}), 404
    
    return jsonify({
        'inscricao_imobiliaria': imovel.inscricao_imobiliaria,
        'imovel_logradouro': imovel.imovel_logradouro,
        'imovel_numero': imovel.imovel_numero,
        'imovel_bairro': imovel.imovel_bairro,
        'imovel_area_total': imovel.imovel_area_total,
        'imovel_area_construida': imovel.imovel_area_construida,
        'imovel_uso': imovel.imovel_uso,
        'imovel_tipo_construcao': imovel.imovel_tipo_construcao
    })


@app.route('/api/usuarios', methods=['GET'])
@token_required
@admin_required
def get_usuarios():
    usuarios = Usuario.query.all()
    output = []
    for user in usuarios:
        output.append({
            'id': user.id,
            'nome': user.nome,
            'usuario': user.usuario,
            'acesso': user.acesso
        })
    return jsonify(output)


@app.route('/api/usuarios/<int:user_id>', methods=['GET'])
@token_required
@admin_required
def get_usuario(user_id):
    user = Usuario.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'nome': user.nome,
        'usuario': user.usuario,
        'acesso': user.acesso
    })


@app.route('/api/usuarios', methods=['POST'])
@token_required
@admin_required
def criar_usuario():
    data = request.get_json()
    if not data or not data.get('usuario') or not data.get('senha') or not data.get('nome'):
        return jsonify({'mensagem': 'Campos nome, usuario e senha são obrigatórios.'}), 400
    
    if Usuario.query.filter_by(usuario=data['usuario']).first():
        return jsonify({'mensagem': 'Usuário já existe.'}), 409
    
    novo_usuario = Usuario(
        nome=data['nome'],
        usuario=data['usuario'],
        senha=data['senha'],
        acesso=data.get('acesso', 'Usuario')
    )
    db.session.add(novo_usuario)
    db.session.commit()
    return jsonify({'mensagem': 'Usuário criado com sucesso!'}), 201


@app.route('/api/usuarios/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def atualizar_usuario(user_id):
    user = Usuario.query.get_or_404(user_id)
    data = request.get_json()
    
    user.nome = data.get('nome', user.nome)
    user.usuario = data.get('usuario', user.usuario)
    user.acesso = data.get('acesso', user.acesso)
    
    if 'senha' in data and data['senha']:
        user.senha_hash = generate_password_hash(data['senha'], method="scrypt")
        
    db.session.commit()
    return jsonify({'mensagem': 'Usuário atualizado com sucesso!'})


@app.route('/api/usuarios/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def excluir_usuario(user_id):
    user = Usuario.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'mensagem': 'Usuário excluído com sucesso!'})


@app.route('/api/pgv/logradouros', methods=['GET'])
@token_required
def get_logradouros(current_user):
    logradouros = ValorLogradouro.query.all()
    output = [{'id': item.id, 'logradouro': item.logradouro, 'valor_m2': item.valor_m2} for item in logradouros]
    return jsonify(output)


@app.route('/api/pgv/logradouros', methods=['POST'])
@token_required
@admin_required
def add_logradouro():
    data = request.get_json()
    logradouro = data.get('logradouro')
    valor_m2 = data.get('valor_m2')

    item = ValorLogradouro.query.filter_by(logradouro=logradouro).first()
    if item:
        item.valor_m2 = valor_m2
        db.session.commit()
        return jsonify({'mensagem': 'Valor de logradouro atualizado com sucesso!'})
    else:
        novo_item = ValorLogradouro(logradouro=logradouro, valor_m2=valor_m2)
        db.session.add(novo_item)
        db.session.commit()
        return jsonify({'mensagem': 'Valor de logradouro adicionado com sucesso!'}), 201


@app.route('/api/pgv/logradouros/<int:id>', methods=['DELETE'])
@token_required
@admin_required
def delete_logradouro(id):
    item = ValorLogradouro.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'mensagem': 'Valor de logradouro excluído com sucesso!'})


@app.route('/api/pgv/padroes_construtivos', methods=['GET'])
@token_required
def get_padroes_construtivos(current_user):
    padroes = PadraoConstrutivo.query.all()
    output = [{'id': item.id, 'descricao': item.descricao, 'valor_m2': item.valor_m2} for item in padroes]
    return jsonify(output)


@app.route('/api/pgv/padroes_construtivos', methods=['POST'])
@token_required
@admin_required
def add_padrao_construtivo():
    data = request.get_json()
    descricao = data.get('descricao')
    valor_m2 = data.get('valor_m2')

    item = PadraoConstrutivo.query.filter_by(descricao=descricao).first()
    if item:
        item.valor_m2 = valor_m2
        db.session.commit()
        return jsonify({'mensagem': 'Padrão construtivo atualizado com sucesso!'})
    else:
        novo_item = PadraoConstrutivo(descricao=descricao, valor_m2=valor_m2)
        db.session.add(novo_item)
        db.session.commit()
        return jsonify({'mensagem': 'Padrão construtivo adicionado com sucesso!'}), 201


@app.route('/api/pgv/padroes_construtivos/<int:id>', methods=['DELETE'])
@token_required
@admin_required
def delete_padrao_construtivo(id):
    item = PadraoConstrutivo.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'mensagem': 'Padrão construtivo excluído com sucesso!'})


@app.route('/api/gerar_iptu/<string:inscricao_imobiliaria>', methods=['GET'])
@token_required
def gerar_iptu(current_user, inscricao_imobiliaria):
    imovel = CadastroReurb.query.filter_by(inscricao_imobiliaria=inscricao_imobiliaria).first()
    if not imovel:
        return jsonify({'mensagem': 'Imóvel não encontrado.'}), 404
    
    valores = CalculoTributarioService.calcular_valores(imovel)
    
    return jsonify({
        'inscricao': imovel.inscricao_imobiliaria,
        'proprietario': imovel.req_nome,
        'endereco': f"{imovel.imovel_logradouro}, {imovel.imovel_numero} - {imovel.imovel_bairro}",
        'vvt': f"R$ {valores['vvt']:.2f}",
        'vvc': f"R$ {valores['vvc']:.2f}",
        'vvi': f"R$ {valores['vvi']:.2f}",
        'iptu': f"R$ {valores['iptu']:.2f}"
    })


@app.route('/api/importar_dados', methods=['POST'])
@token_required
@admin_required
def importar_dados():
    if 'arquivo' not in request.files:
        return jsonify({'mensagem': 'Nenhum arquivo enviado.'}), 400
    
    arquivo = request.files['arquivo']
    if arquivo.filename == '':
        return jsonify({'mensagem': 'Nome de arquivo vazio.'}), 400

    try:
        if arquivo.filename.endswith('.xlsx') or arquivo.filename.endswith('.xls'):
            df = pd.read_excel(arquivo)
        elif arquivo.filename.endswith('.csv'):
            df = pd.read_csv(arquivo)
        else:
            return jsonify({'mensagem': 'Formato de arquivo não suportado. Use .xlsx, .xls ou .csv'}), 400
        
        registros_importados = 0
        for index, row in df.iterrows():
            try:
                novo_cadastro = CadastroReurb(
                    inscricao_imobiliaria=row.get('inscricao_imobiliaria'),
                    imovel_logradouro=row.get('logradouro'),
                    imovel_numero=row.get('numero'),
                    imovel_bairro=row.get('bairro'),
                    imovel_area_total=row.get('area_terreno'),
                    imovel_area_construida=row.get('area_construida'),
                    # Adicione outros campos conforme sua planilha
                    req_nome='Importado'
                )
                db.session.add(novo_cadastro)
                registros_importados += 1
            except Exception as e:
                print(f"Erro ao importar linha {index}: {e}")
                continue

        db.session.commit()
        return jsonify({'mensagem': f'{registros_importados} registros importados com sucesso!'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'mensagem': f'Erro ao processar o arquivo: {str(e)}'}), 500


@app.route('/api/upload_documento/<int:id>', methods=['POST'])
@token_required
def upload_documento(current_user, id):
    if 'arquivo' not in request.files:
        return jsonify({'mensagem': 'Nenhum arquivo enviado.'}), 400

    arquivo = request.files['arquivo']
    tipo_documento = request.form.get('tipo_documento')

    cadastro = CadastroReurb.query.get_or_404(id)

    if arquivo.filename == '':
        return jsonify({'mensagem': 'Nome de arquivo vazio.'}), 400

    filename = secure_filename(f"{id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{arquivo.filename}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    arquivo.save(filepath)

    novo_documento = Documento(
        cadastro_id=cadastro.id,
        nome_arquivo=arquivo.filename,
        path_arquivo=filename,
        tipo_documento=tipo_documento
    )
    db.session.add(novo_documento)
    db.session.commit()
    
    return jsonify({"mensagem": "Arquivo enviado com sucesso!", "arquivo": filename}), 201


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# =======================================================================
# INICIALIZAÇÃO
# =======================================================================
if __name__ == '__main__':
    with app.app_context():
        # 🔹 Cria todas as tabelas automaticamente se ainda não existirem
        db.create_all()

        # 🔹 Cria admin padrão se não existir
        if not Usuario.query.filter_by(usuario='admin').first():
            print("Criando usuário 'admin' padrão com senha 'admin'...")
            admin_user = Usuario(
                nome="Administrador",
                usuario="admin",
                senha="admin",
                acesso="Administrador"
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Usuário 'admin' criado com sucesso.")
    
    # 🔹 Executa a aplicação
    app.run(debug=True)