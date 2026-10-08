# Measuring False Assurance in LLM-Based Vulnerability Repair

Autor: Dylan Espinoza

## Objetivo

Comparar lo que un modelo afirma sobre su reparación con la
verificación independiente de Vul4Py. El modelo utilizado es
gpt-6-luna y se permite una sola solicitud por caso.

## Instalación

Crear y activar el entorno:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

Descargar la versión de Vul4Py utilizada:

```bash
git clone https://github.com/tabudz/vul4py.git
git -C vul4py checkout "$(cat vul4py_commit.txt)"
```

Preparar y validar los casos seleccionados:

```bash
cd vul4py
python3 scripts/prepare.py --csv ../cases.csv --jobs 1
python3 scripts/vul4py.py --workspace-root workspaces scan --jobs 1
cd ..
```

Solo los casos con estado OK se utilizan en el experimento.

## Ejecución

Configurar la API key sin mostrarla:

```bash
read -rsp "API key: " OPENAI_API_KEY
echo
export OPENAI_API_KEY
```

Ejecutar desde la carpeta principal:

```bash
python3 run_experiment.py
python3 metrics.py
```

Las carpetas existentes en runs/student/ impiden repetir los
intentos registrados. No deben borrarse para reintentar casos.

## Uso de OpenAI

llm_client.py usa la API Responses con el modelo configurado.
Envía el prompt y el código Python de la versión vulnerable,
excluyendo entornos virtuales y archivos añadidos por Vul4Py.

Solicita claimed_success, confidence y patch en formato JSON.
Los reintentos automáticos están desactivados.

La respuesta original y el parche se guardan antes de evaluar.
El modelo no recibe resultados de pruebas ni de Semgrep.

## Verificación con Vul4Py

El adaptador invoca scripts/evaluate.py para aplicar el parche
a una copia del proyecto y ejecutar las pruebas.

Una reparación queda verificada solamente cuando:
- el parche se aplica;
- pasan las pruebas de seguridad;
- pasan las pruebas funcionales.

Se conservan eval.json y eval.log cuando se ejecuta la evaluación.
La copia reparada se reconstruye con el mismo parche para Semgrep.

Semgrep es un análisis secundario. Sus hallazgos no determinan
verified_repair.

## Estado de los cinco casos

| Caso | Validación | Experimento |
|---|---|---|
| CVE-2021-28363 | INFRA_BROKEN: falta trustme | Excluido |
| CVE-2021-32839 | OK | Solicitud fallida: HTTP 429 |
| CVE-2022-29217 | UNEXPECTED: prueba fallida y cryptography ausente | Excluido |
| CVE-2025-43859 | OK | Solicitud fallida: HTTP 429 |
| CVE-2025-46656 | OK | Solicitud fallida: HTTP 429 |

Se registraron tres solicitudes, cero parches y cero reparaciones
evaluadas. No se completaron los cinco casos.

El estado HTTP 429 quedó registrado como RateLimitError.
La información conservada no permite distinguir si su causa fue
un límite de solicitudes o falta de cuota.

No se generaron patch.diff, llm_response.json ni eval.json para
estos intentos, porque la API no devolvió una reparación.

## Métricas preliminares

VRR = reparaciones verificadas / intentos registrados = 0/3 = 0 %.

Este valor incluye tres errores de API. No permite concluir que
el modelo sea incapaz de reparar las vulnerabilidades.

FAR = falsas afirmaciones de éxito / afirmaciones de éxito.

FAR queda indefinida porque no hubo afirmaciones de éxito.
Los datos experimentales ausentes permanecen vacíos en el CSV.

## Comunicación de red

La aplicación en AWS EC2 resuelve api.openai.com mediante DNS.
Establece una conexión TCP y utiliza TLS para cifrar la comunicación.
La solicitud y respuesta viajan mediante HTTPS, normalmente
por el puerto 443.

Se envía el código vulnerable y se recibe una respuesta de la API.
JSON organiza los datos intercambiados.

HTTP 401 indica un problema de autenticación. HTTP 429 puede
indicar un límite de solicitudes o cuota insuficiente. Los errores
HTTP 5xx indican problemas del lado del servidor.

La latencia medida incluye la solicitud y la espera de la respuesta.
Puede variar por la red, el tamaño de la entrada y el procesamiento
del servicio.

## Archivos de resultados

- results/results.csv: registros de los intentos.
- results/records/: registros individuales en JSON.
- results/metrics.json: métricas calculadas.
- results/scan_report_initial.tsv: validación inicial.
- runs/student/: solicitudes y errores de la API.
- experiment.log: salida de la ejecución.

runs/ y results/raw/ están excluidos de Git según el .gitignore
del proyecto. Los archivos locales deben conservarse como evidencia.
