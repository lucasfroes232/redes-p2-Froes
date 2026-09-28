import asyncio
import time
import random
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # Passo 1: cliente pedindo para abrir conexão nova.
            # Passamos o seq_no do cliente para a Conexao poder calcular o ack_no inicial
            # e fazer o handshake (SYN+ACK) já no construtor.
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no_cliente):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.fechada = False   # Passo 4: trava para ignorar tudo após o fechamento

        # --- Passo 1/2: números de sequência ---
        self.seq_no = random.randint(0, 0xffff)   # nosso próximo número de sequência a enviar
        self.ack_no = seq_no_cliente + 1           # próximo byte esperado do cliente (SYN consome 1)

        # --- Passos 5/6: retransmissão e RTT ---
        self.enviados_nao_confirmados = []   # [{seq, dados, timestamp, retransmitido}]
        self.fila_envio = []                 # pedaços de até MSS bytes ainda não enviados
        self.timer = None
        self.timer_interval = 1              # valor base (segundos), recalculado após cada RTT medido
        self.estimated_rtt = None
        self.dev_rtt = None

        # --- Passo 7: controle de congestionamento (AIMD) ---
        self.cwnd = MSS
        self.bytes_confirmados_na_janela = 0
        self.backoff = 1   # multiplicador de backoff exponencial, resetado a cada ACK com progresso

        # --- Passo 1: handshake — responde ao SYN com SYN+ACK ---
        self._enviar_flags(b'', FLAGS_SYN | FLAGS_ACK)
        self.seq_no += 1   # o próprio SYN consome um número de sequência

    # ---------------------------------------------------------------
    # Infraestrutura de envio de segmentos
    # ---------------------------------------------------------------

    def _montar_segmento(self, seq_no, dados, flags):
        # Nosso id_conexao guarda (endereço_cliente, porta_cliente, endereço_servidor, porta_servidor).
        # Quando enviamos, nós somos o servidor: origem = porta do servidor, destino = porta do cliente.
        end_cliente, porta_cliente, end_servidor, porta_servidor = self.id_conexao
        segmento = make_header(porta_servidor, porta_cliente, seq_no, self.ack_no, flags)
        segmento += dados
        segmento = fix_checksum(segmento, end_servidor, end_cliente)
        return segmento

    def _enviar_flags(self, dados, flags):
        """Envia um segmento avulso (sem controle de retransmissão), ex: ACK puro, SYN+ACK, FIN."""
        end_cliente, _, _, _ = self.id_conexao
        segmento = self._montar_segmento(self.seq_no, dados, flags)
        self.servidor.rede.enviar(segmento, end_cliente)

    def _transmitir_dados(self, seq_no, dados, flags=FLAGS_ACK):
        """Envia (ou reenvia) um segmento de dados já registrado em enviados_nao_confirmados."""
        end_cliente, _, _, _ = self.id_conexao
        segmento = self._montar_segmento(seq_no, dados, flags)
        self.servidor.rede.enviar(segmento, end_cliente)

    # ---------------------------------------------------------------
    # Passo 2: recebimento de segmentos
    # ---------------------------------------------------------------

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.fechada:
            return  # Passo 4: não processa mais nada depois de fechada

        if (flags & FLAGS_ACK) == FLAGS_ACK:
            self._tratar_ack(ack_no)

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            # Passo 4: pedido de fechamento de conexão
            if seq_no == self.ack_no:
                self.ack_no += 1   # o FIN também consome um número de sequência
                self._enviar_flags(b'', FLAGS_ACK)
                self.fechada = True
                self._parar_timer()
                if self.callback:
                    self.callback(self, b'')   # avisa a aplicação que a conexão fechou
            return

        if not payload:
            return  # segmento vazio (por exemplo, um ACK puro): nada a entregar

        if seq_no != self.ack_no:
            # Fora de ordem ou duplicado: descarta e reafirma o ACK esperado
            self._enviar_flags(b'', FLAGS_ACK)
            return

        self.ack_no += len(payload)
        self._enviar_flags(b'', FLAGS_ACK)
        if self.callback:
            self.callback(self, payload)

    # ---------------------------------------------------------------
    # Passos 5, 6 e 7: envio, retransmissão, RTT e congestionamento
    # ---------------------------------------------------------------

    def _iniciar_timer(self):
        self._parar_timer()
        self.timer = asyncio.get_event_loop().call_later(
            self.timer_interval * self.backoff, self._timeout
        )

    def _parar_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    def _timeout(self):
        # Passo 7: perda detectada -> reduz a janela de congestionamento pela metade
        self.cwnd = max(MSS, self.cwnd / 2)
        self.timer = None

        if self.enviados_nao_confirmados:
            seg = self.enviados_nao_confirmados[0]
            seg['retransmitido'] = True   # não usar essa retransmissão para medir RTT (algoritmo de Karn)
            self._transmitir_dados(seg['seq'], seg['dados'])

            # Backoff exponencial: dobra o intervalo a cada timeout consecutivo sem
            # nenhum ACK no meio, para não ficar retransmitindo em cascata antes do
            # ACK da retransmissão anterior ter tempo de voltar.
            self.backoff *= 2
            self._iniciar_timer()

    def _atualizar_rtt(self, sample_rtt):
        # Passo 6: cálculo do TimeoutInterval segundo a RFC 2988
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            alpha, beta = 0.125, 0.25
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt
        self.timer_interval = self.estimated_rtt + 4 * self.dev_rtt

    def _tratar_ack(self, ack_no):
        bytes_confirmados = 0

        # ACKs no TCP são cumulativos: removemos tudo que já foi confirmado
        while self.enviados_nao_confirmados and \
                self.enviados_nao_confirmados[0]['seq'] + len(self.enviados_nao_confirmados[0]['dados']) <= ack_no:
            seg = self.enviados_nao_confirmados.pop(0)
            bytes_confirmados += len(seg['dados'])

            if not seg.get('retransmitido'):
                # Passo 6: só medimos RTT de segmentos que não foram retransmitidos (algoritmo de Karn)
                self._atualizar_rtt(time.time() - seg['timestamp'])

        if bytes_confirmados > 0:
            self.backoff = 1   # qualquer progresso confirmado desfaz o backoff acumulado

            # Passo 7: a cada janela inteira confirmada, cresce 1 MSS (AIMD - fase aditiva)
            self.bytes_confirmados_na_janela += bytes_confirmados
            while self.bytes_confirmados_na_janela >= self.cwnd:
                self.bytes_confirmados_na_janela -= self.cwnd
                self.cwnd += MSS

            if self.enviados_nao_confirmados:
                self._iniciar_timer()   # ainda há dados em voo: reinicia o timer
            else:
                self._parar_timer()     # tudo confirmado: não precisa de timer

        self._tentar_enviar_fila()

    def _tentar_enviar_fila(self):
        # Passo 5/7: respeita a janela de congestionamento (cwnd) ao decidir o que enviar agora
        bytes_em_voo = sum(len(s['dados']) for s in self.enviados_nao_confirmados)

        while self.fila_envio and bytes_em_voo + len(self.fila_envio[0]) <= self.cwnd:
            dados = self.fila_envio.pop(0)
            seg = {'seq': self.seq_no, 'dados': dados, 'timestamp': time.time(), 'retransmitido': False}
            self.enviados_nao_confirmados.append(seg)
            self._transmitir_dados(seg['seq'], dados)
            self.seq_no += len(dados)
            bytes_em_voo += len(dados)

            if self.timer is None:
                self._iniciar_timer()

    # ---------------------------------------------------------------
    # API usada pela camada de aplicação
    # ---------------------------------------------------------------

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # Passo 3: quebra os dados em pedaços de até MSS bytes
        for i in range(0, len(dados), MSS):
            self.fila_envio.append(dados[i:i+MSS])
        self._tentar_enviar_fila()

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # Passo 4: envia FIN (assumimos que o cliente fecha primeiro, então aqui só respondemos)
        self._enviar_flags(b'', FLAGS_FIN | FLAGS_ACK)
        self.seq_no += 1
        self.fechada = True
        self._parar_timer()