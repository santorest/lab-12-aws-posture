---
title: "Auditoría de postura de seguridad en AWS (emulada)"
id: "lab-12-aws-posture"
category: "Seguridad en la nube"
type: "Laboratorio"
status: "en curso"
date: "2026-10-06"
time_to_reproduce: "Unos 10 minutos: una ejecución de CI (fork, habilitar Actions, ejecutar CI); el trabajo de auditoría tarda de 3 a 5 minutos"
skills: [AWS, LocalStack, Terraform, Prowler, Checkov, Python, boto3, GitHub Actions]
frameworks: [CIS AWS Foundations Benchmark v7.0, CIS Controls v8 (3.3, 3.11, 4.4, 4.5, 5.4, 6.5, 13.6), MITRE ATT&CK (T1530, T1078.004, T1562.007)]
repo: "https://github.com/santorest/lab-12-aws-posture"
bundle: "Publicado en el sitio del portafolio con su suma SHA-256"
---

# Auditoría de postura de seguridad en AWS (emulada)

> **Resumen:** La cuenta de AWS de una pequeña empresa, armada a mano, se reconstruye con Terraform sobre LocalStack
> con configuraciones erróneas documentadas sembradas a propósito: un bucket público, datos de clientes sin cifrar con
> la llave de la empresa y sin versiones, una política de todo sobre todo, una llave de acceso de larga duración sin
> MFA, una política de contraseñas débil, SSH y RDP abiertos a internet, un grupo de seguridad por defecto abierto, una
> llave sin rotación y una VPC sin registros de flujo. Prowler audita la cuenta antes y después de una corrección en
> Terraform; CI falla salvo que cada falla sembrada se haya detectado y luego corregido, no haya aparecido nada nuevo y
> el desmontaje no haya dejado nada. **Las ejecuciones de CI son reales; la cuenta de AWS es emulada (LocalStack); no se
> usa ninguna cuenta real de AWS.**

| | |
|---|---|
| **Rol desempeñado** | Ingeniero de seguridad en la nube que revisa la cuenta de AWS de una pequeña empresa |
| **Entorno** | Repositorio público en GitHub, runners Ubuntu alojados por GitHub, LocalStack 4.14.0 (edición comunitaria) |
| **Herramientas** | Terraform 1.16 + proveedor AWS 6.67, Prowler 5.44.0, Checkov, Python 3.12, boto3, moto, pytest, ruff, mypy, tflint, shellcheck, gitleaks |
| **Entregable** | Terraform con una postura vulnerable y una corregida, fallas sembradas como datos, herramienta de auditoría-comparación-compuerta (`postureck`), CI, ruleset de rama, PR de demostración |

---

## 1. Problema

Las pequeñas empresas suelen configurar su cuenta en la nube a mano, con prisa, y nunca la revisan: un bucket abierto
"por un minuto", un usuario de despliegue con todos los permisos, una llave que nunca vence, el puerto de la base de
datos abierto para un contratista. Una herramienta de auditoría lista cientos de hallazgos; lo que falta es una forma
de demostrar que las fallas que importan se encontraron, que la corrección las eliminó y que la corrección no abrió
otra cosa.

## 2. Diseño

- **La cuenta como código.** Terraform construye la cuenta en dos posturas a partir de los mismos recursos: una
  variable por falla sembrada la activa (`envs/vulnerable.tfvars`) o la desactiva (`envs/remediated.tfvars`). Ambas se
  aplican al mismo estado, así que la corrección es un cambio sobre los mismos recursos — como llega una corrección
  real.
- **Fallas sembradas como datos.** `policy/misconfigs.yml` lista cada parte sembrada, su id de CIS AWS Foundations y
  las verificaciones que deben detectarla. El papel de cada herramienta se fija de antemano: una falla que nadie
  detecta es un hallazgo sobre la auditoría, no un aprobado.
- **Un auditor independiente.** La auditoría la hace Prowler. Donde Prowler no tiene una verificación para una falla
  sembrada en el emulador, una pequeña verificación de respaldo en `postureck` la cubre, y cada hallazgo indica la
  herramienta que lo produjo.
- **Una correspondencia que no se desvía.** Los hallazgos se identifican por (verificación, recurso). Los grupos de
  seguridad, las VPC y las llaves tienen ids aleatorios, así que se reconocen por su etiqueta Name exacta, que Prowler
  informa como label. Después de la corrección, cada elemento sembrado se juzga sobre los pares exactos (verificación,
  recurso) que fallaron antes: una etiqueta renombrada, un aprobado en otro recurso o una verificación que queda en
  silencio no pueden hacer que una falla parezca corregida.
- **Un desmontaje que se verifica.** El emulador trae sus propios recursos de ejemplo, así que el desmontaje se
  compara con un inventario tomado antes de crear nada.

## 3. El ciclo

1. Iniciar LocalStack (fijado por digest) y tomar el inventario de referencia.
2. `terraform apply` de la postura vulnerable.
3. Auditoría: Prowler sobre S3, IAM, EC2, VPC y KMS incluyendo recursos sin uso (la cuenta emulada no tiene cargas de
   trabajo), más la verificación de respaldo.
4. `terraform apply` de la postura corregida sobre el mismo estado.
5. Auditoría de nuevo.
6. `terraform destroy`; el inventario debe coincidir con el de referencia.
7. `postureck report` compara y escribe HTML, Markdown y JSON; `postureck gate` decide.

## 4. Medición y compuerta

- **Tasa de detección**: elementos sembrados cuyas verificaciones fallaron antes de la corrección (un elemento con dos
  partes cuenta cuando ambas se detectaron). **Tasa de corrección**: elementos sembrados que cumplen después de la
  corrección (una parte exceptuada no cuenta como corregida).
- **Regresiones**: una (verificación, recurso) que falla después de la corrección y no fallaba antes.
- **Abiertos**: fallan antes y después, no sembrados — se reportan, no detienen.
- **Compuerta** (código 1): una falla sembrada no detectada; una falla sembrada que sigue fallando, o cuya
  verificación quedó en silencio, después de la corrección; cualquier regresión, aunque los totales hayan bajado;
  recursos que quedan después del desmontaje.
- **Errores, no resultados** (código 2): LocalStack no está sano, un paso de Terraform falló, Prowler no escribió
  salida, un archivo de hallazgos no se puede leer o un servicio desplegado no tiene ningún hallazgo de ninguna
  herramienta.

## 5. Configuraciones erróneas sembradas

| Elemento | Configuración errónea | CIS v7.0 | Detectado por |
|---|---|---|---|
| 1 | Bucket de recursos web legible por cualquiera, Block Public Access desactivado | 3.1.4 | Prowler |
| 2a | Datos de clientes no cifrados con la llave KMS de la empresa | fuera de CIS 7.0 | Prowler |
| 2b | Bucket de datos de clientes sin versiones y accesible por HTTP | 3.1.1 | Prowler |
| 3 | Política que permite todas las acciones sobre todos los recursos, asignada a un usuario | 2.14 | Prowler |
| 4a | Llave de acceso de larga duración en un usuario sin MFA | 2.10 | postureck |
| 4b | Política de contraseñas débil | 2.8, 2.9 | Prowler |
| 6a | SSH y RDP abiertos a internet | 6.3 | Prowler |
| 6b | El grupo de seguridad por defecto permite tráfico | 6.5 | Prowler |
| 7a | Llave KMS sin rotación | 4.6 | Prowler |
| 7b | VPC sin registros de flujo | 4.7 | Prowler |

El elemento 5 del plan, la ausencia de CloudTrail, no se siembra: la edición de LocalStack que funciona sin token no
tiene el servicio CloudTrail.

## 6. Pipeline

| Trabajo | Qué prueba |
|---|---|
| `lint` | terraform fmt/validate, tflint (conjunto de reglas de AWS), ruff, mypy (estricto), shellcheck, yamllint |
| `unit` | `postureck` sobre datos de prueba recortados de salidas reales de Prowler y sobre moto; `terraform test` con un proveedor simulado; cobertura mínima 90 % |
| `iac-scan` | Checkov sobre ambas posturas, como comparación (no detiene) |
| `audit` | el ciclo completo en LocalStack; artefactos: salida de Prowler, hallazgos de respaldo, registros de Terraform, inventarios, informe |
| `secrets` | gitleaks sobre todo el historial |

Se ejecuta en cada pull request, en cada push a `main`, semanalmente y a demanda.

## 7. Resultados

De la [ejecución 37812253346](https://github.com/santorest/lab-12-aws-posture/actions/runs/37812253346) (2026-10-08), el código final tras las correcciones de la revisión; la primera en verde, [37414269426](https://github.com/santorest/lab-12-aws-posture/actions/runs/37414269426) en `main` (2026-10-06), dio las mismas cifras.
`docs/example-report.html` es su informe. LocalStack 4.14.0 (edición comunitaria, fijada por digest), Prowler 5.44.0,
Terraform 1.16.5 con el proveedor de AWS 6.67.0, CIS AWS Foundations v7.0 según el mapeo de Prowler.

| | Antes de la corrección | Después de la corrección |
|---|---|---|
| Elementos sembrados detectados | **6 / 6** (las 10 partes) | — |
| Elementos sembrados que cumplen | 0 / 6 | **6 / 6** (las 10 partes) |
| Regresiones | — | **0** |
| Recursos que quedan tras el desmontaje | — | **0** |

- **Cada parte sembrada la detectó la herramienta asignada**: nueve Prowler y una (la llave de acceso sin MFA) la
  verificación de respaldo, porque Prowler solo revisa el MFA de usuarios con acceso a la consola.
- **Hallazgos que fallan por sección de CIS** (las partes sembradas y todo lo demás que Prowler informa sobre los cinco
  servicios): sección 2 (identidad) 7 → 3, sección 3 (almacenamiento) 6 → 4, sección 4 (registros y llaves) 3 → 1,
  sección 6 (redes) 11 → 8.
- **Hallazgos abiertos: lea los totales con cuidado.** 1.201 hallazgos fallan antes y después de la corrección. Solo 20
  están en los recursos del propio laboratorio — controles fuera del conjunto sembrado, como replicación, reglas de
  ciclo de vida, object lock, registro de accesos y MFA delete en los dos buckets, o MFA de hardware en el usuario de
  despliegue — y se reportan, no se ocultan. Los otros 1.181 pertenecen al emulador: 1.159 son "instantánea de EBS sin
  cifrar" sobre las instantáneas de ejemplo que trae LocalStack, que existen antes de que el laboratorio cree nada. Por
  eso los totales por severidad apenas se mueven (alta 1.181 → 1.171): la compuerta juzga los elementos sembrados, las
  regresiones y el desmontaje, no los totales.
- **Tiempo**: el paso de auditoría tarda unos 3 minutos (dos aplicaciones de Terraform, dos escaneos de Prowler de unos
  30 segundos, un destroy); el pipeline completo, de 4 a 6 minutos.

**Cómo se llegó ahí.** El primer ciclo completo ([ejecución 37413720116](https://github.com/santorest/lab-12-aws-posture/actions/runs/37413720116)) detectó 6/6 pero
corrigió 5/6 y encontró una regresión. El grupo de seguridad por defecto conservó sus reglas después de la
"corrección": Terraform trata los bloques de reglas vacíos como "no especificado", así que no se eliminó nada — ahora
las reglas se escriben como una lista vacía explícita. Y la regresión era real: el rol de IAM que la corrección creó
para los registros de flujo de la VPC podía asumirse en nombre de cualquier cuenta (sin condición
`aws:SourceAccount`). La corrección había introducido una debilidad nueva, y la verificación de regresiones fue la que
la encontró.

**Escaneo estático, como comparación.** Checkov, ejecutado sobre ambas posturas, no informó la regla de SSH/RDP
abierta a internet en ninguna de las dos: el rango de direcciones sale de un valor condicional que no resuelve. La
auditoría en vivo sí.

**Pull requests de demostración** (cerrados sin fusionar; el ruleset bloquea la fusión):

| PR | Cambio | Qué pasó |
|---|---|---|
| [#1](https://github.com/santorest/lab-12-aws-posture/pull/1) | SSH y RDP abiertos a internet otra vez en la postura corregida | detectados 6/6 pero corregidos 5/6: la compuerta falló con "planted flaw still failing after fix: P6a" |
| [#2](https://github.com/santorest/lab-12-aws-posture/pull/2) | la "corrección" crea además un bucket público nuevo, `acme-exports` | todos los elementos sembrados siguieron corregidos (6/6), pero la compuerta falló por 12 regresiones en el bucket nuevo, entre ellas acceso público (crítica) y Block Public Access desactivado (alta) |

## 8. Lecciones

- **El emulador gratuito cambió.** Las versiones actuales de LocalStack no arrancan sin un token de cuenta; la última
  versión sin token (4.14.0, edición comunitaria) funciona, pero no tiene CloudTrail — así que una de las fallas
  sembradas tuvo que salir, y el informe lo dice en lugar de fingirlo.
- **"Revisar solo lo que se usa" oculta una cuenta emulada.** Por defecto Prowler omite los recursos que nada usa; en
  una cuenta sin cargas de trabajo eso significa que los grupos de seguridad y la VPC nunca se revisaban. La auditoría
  incluye a propósito los recursos sin uso.
- **Un filtro de cumplimiento no es la auditoría.** Ejecutar Prowler con `--compliance` lo limita a las verificaciones
  de ese marco; revisar por servicio mantiene todas las verificaciones y aun así registra el id de CIS en cada hallazgo.
- **Los valores por defecto cambian lo que se puede sembrar.** S3 ahora cifra cada bucket con SSE-S3 por defecto, en
  AWS y en el emulador, así que "sin cifrado alguno" no se puede sembrar; el elemento pasó a ser "no cifrado con la
  llave propia de la empresa".
- **Una corrección puede abrir algo nuevo.** El rol de registros de flujo que agregó la corrección podía asumirse
  en nombre de cualquier cuenta; los totales igual bajaron, y solo la verificación de regresiones (un hallazgo ausente
  antes que falla después) lo detectó.
- **Vacío no es lo mismo que "eliminar".** Terraform trata los bloques de reglas vacíos del grupo de seguridad por
  defecto como "no especificado" y deja las reglas anteriores; una lista vacía explícita las elimina. Un plan con
  proveedores simulados no puede mostrarlo — lo mostraron la aplicación real y la segunda auditoría.
- **Los ids aleatorios necesitan nombres.** Los grupos de seguridad, las VPC y las llaves vuelven con ids aleatorios;
  etiquetarlos con un Name y reconocerlos por los labels de Prowler es lo que permite seguir una falla sembrada de
  antes a después.

## 9. Límites

- El objetivo es AWS emulado (LocalStack 4.14.0 comunitario), no una cuenta real; los resultados muestran que el
  método funciona, no la postura de ninguna cuenta real.
- La cobertura de Prowler en el emulador es parcial; el informe indica la herramienta detrás de cada hallazgo.
- No se puede probar aquí: CloudTrail, los controles de la cuenta raíz, GuardDuty, Security Hub, Organizations.
- El emulador trae recursos de ejemplo (por ejemplo instantáneas de EC2); sus hallazgos fallan antes y después e
  inflan los totales. Lo que juzga la compuerta son los elementos sembrados, las regresiones y el desmontaje.

## 10. Reproducirlo

Haga un fork del repositorio y habilite Actions: cada push ejecuta el ciclo. En local (Linux, macOS o WSL con Docker,
Terraform y Python 3.12), siga el inicio rápido del README: `bash scripts/run-audit.sh` escribe `out/report.html` y
`out/results.json`.

## 11. Mapeo

| Marco | Elementos |
|---|---|
| CIS AWS Foundations v7.0 | 2.8, 2.9, 2.10, 2.14, 3.1.1, 3.1.4, 4.6, 4.7, 6.3, 6.5 |
| CIS Controls v8 | 3.3 configurar listas de control de acceso a datos, 3.11 cifrar datos sensibles en reposo, 4.4 y 4.5 firewalls en servidores y equipos de usuario, 5.4 restringir privilegios de administrador, 6.5 exigir MFA para el acceso administrativo, 13.6 recolectar registros de flujo de tráfico de red |
| MITRE ATT&CK | T1530 Data from Cloud Storage, T1078.004 Valid Accounts: Cloud Accounts, T1562.007 Impair Defenses: Disable or Modify Cloud Firewall — lo que los ajustes corregidos dificultan |
