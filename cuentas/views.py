import logging
import secrets
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_not_required
from django.core.cache import cache
from django.core.mail import send_mail
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from core.crud import Columna, Filtro, Mantenedor, filtro_estado
from core.middleware import CLAVE_SESION
from core.permisos import ACCIONES, NOMBRE_MODULO

from .backends import buscar_por_identificador
from .forms import (LoginForm, NuevaClaveForm, RolForm, SolicitarCodigoForm, UsuarioForm,
                    ValidarCodigoForm)
from .models import Rol, SolicitudRecuperacion, Usuario
from .validadores import REQUISITOS_CLAVE

log = logging.getLogger("sgr")

SESION_RECUPERACION = "recuperacion"
MENSAJE_GENERICO = ("Si el correo corresponde a una cuenta activa, recibirá un código de 6 dígitos. "
                    "Revise su bandeja de entrada y la carpeta de correo no deseado.")


# =============================================================================
# Acceso
# =============================================================================
def _clave_intentos(identificador):
    return "login-intentos:" + (identificador or "").strip().lower()[:120]


@login_not_required
def ingresar(request):
    if request.user.is_authenticated:
        return redirect("core:inicio")
    form = LoginForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        identificador = form.cleaned_data["identificador"]
        clave_cache = _clave_intentos(identificador)
        intentos = cache.get(clave_cache, 0)
        if intentos >= settings.LOGIN_MAX_INTENTOS:
            form.add_error(None, f"Demasiados intentos fallidos. Espere {settings.LOGIN_BLOQUEO_MINUTOS} "
                                 "minutos e intente nuevamente, o recupere su contraseña.")
        else:
            usuario = buscar_por_identificador(identificador)
            if usuario and usuario.check_password(form.cleaned_data["clave"]):
                if not usuario.is_active:
                    form.add_error(None, "Su cuenta está inactiva. Contacte al administrador del sistema.")
                elif not usuario.rol.activo:
                    form.add_error(None, "Su rol está inactivo. Contacte al administrador del sistema.")
                elif not usuario.delegaciones_autorizadas().exists():
                    form.add_error(None, "Su cuenta no tiene una delegación activa asignada. "
                                         "Contacte al administrador del sistema.")
                else:
                    cache.delete(clave_cache)
                    login(request, usuario, backend="cuentas.backends.UsuarioOCorreoBackend")
                    request.session[CLAVE_SESION] = usuario.delegaciones_autorizadas().order_by("codigo").first().pk
                    
                    # SI EL USUARIO TIENE PENDIENTE CAMBIAR LA CLAVE PROVISORIA
                    if getattr(usuario, "debe_cambiar_clave", False):
                        messages.warning(request, "Por seguridad, debe cambiar su contraseña provisoria antes de continuar.")
                        solicitud, _ = SolicitudRecuperacion.crear(usuario)
                        solicitud.verificado_en = timezone.now()
                        solicitud.save()
                        request.session[SESION_RECUPERACION] = {
                            "token": solicitud.token,
                            "correo": usuario.correo,
                            "verificado": True,
                        }
                        return redirect("cuentas:nueva_clave")

                    messages.success(request, f"Bienvenido(a), {usuario.nombre}.")
                    destino = request.POST.get("next") or request.GET.get("next")
                    if destino and url_has_allowed_host_and_scheme(destino, {request.get_host()},
                                                                   request.is_secure()):
                        return redirect(destino)
                    return redirect("core:inicio")
            else:
                cache.set(clave_cache, intentos + 1, settings.LOGIN_BLOQUEO_MINUTOS * 60)
                restantes = settings.LOGIN_MAX_INTENTOS - intentos - 1
                texto = "Usuario/correo o contraseña incorrectos. Verifique sus datos."
                if 0 < restantes <= 2:
                    texto += f" Le quedan {restantes} intento(s) antes del bloqueo temporal."
                form.add_error(None, texto)
    return render(request, "auth/login.html", {
        "form": form, "next": request.GET.get("next", ""),
        "errores_formulario": request.method == "POST" and bool(form.errors),
    })


@require_POST
def salir(request):
    logout(request)
    messages.success(request, "Sesión cerrada correctamente.")
    return redirect("cuentas:login")


# =============================================================================
# Recuperación de contraseña
# =============================================================================
def _enviar_codigo(usuario, codigo):
    try:
        send_mail(
            "SGR La Serena · Código de recuperación de contraseña",
            f"Hola {usuario.nombre}:\n\n"
            f"Su código de verificación es: {codigo}\n\n"
            f"El código vence en {settings.RECUPERACION_VIGENCIA_MINUTOS} minutos y solo puede usarse una vez.\n"
            "Si usted no solicitó este cambio, ignore este mensaje: su contraseña no será modificada.\n\n"
            "Sistema de Gestión de Requerimientos · Ilustre Municipalidad de La Serena",
            None, [usuario.correo],
        )
    except Exception:  # noqa: BLE001 - no se revela el fallo al solicitante
        log.exception("No fue posible enviar el código de recuperación a %s", usuario.pk)


def _flujo(request):
    return request.session.get(SESION_RECUPERACION)


def _solicitud(flujo):
    if not flujo:
        return None
    return SolicitudRecuperacion.objects.select_related("usuario").filter(token=flujo["token"]).first()


@login_not_required
def solicitar_codigo(request):
    form = SolicitarCodigoForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        correo = form.cleaned_data["correo"].lower()
        usuario = Usuario.objects.filter(correo__iexact=correo, is_active=True).first()
        token = secrets.token_urlsafe(32)
        if usuario:
            hace_una_hora = timezone.now() - timedelta(hours=1)
            recientes = usuario.solicitudes_recuperacion.filter(creado__gte=hace_una_hora).count()
            if recientes < settings.RECUPERACION_MAX_SOLICITUDES_HORA:
                with transaction.atomic():
                    usuario.solicitudes_recuperacion.filter(usado_en__isnull=True).update(anulado=True)
                    solicitud, codigo = SolicitudRecuperacion.crear(usuario)
                _enviar_codigo(usuario, codigo)
                token = solicitud.token
            else:
                log.warning("Límite de solicitudes de recuperación alcanzado para usuario %s", usuario.pk)
        ahora = timezone.now()
        request.session[SESION_RECUPERACION] = {
            "token": token,
            "correo": correo,
            "intentos_simulados": 0,
            "envio_simulado": ahora.isoformat(),
            "verificado": False,
        }
        messages.info(request, MENSAJE_GENERICO)
        return redirect("cuentas:validar_codigo")
    return render(request, "auth/recuperar.html", {
        "form": form, "errores_formulario": request.method == "POST" and bool(form.errors)})


def _estado_tiempos(flujo, solicitud):
    if solicitud:
        return solicitud.expira, solicitud.segundos_para_reenvio(), solicitud.reenvios
    envio = datetime.fromisoformat(flujo["envio_simulado"])
    expira = envio + timedelta(minutes=settings.RECUPERACION_VIGENCIA_MINUTOS)
    espera = envio + timedelta(seconds=settings.RECUPERACION_ESPERA_REENVIO_SEG)
    return expira, max(0, int((espera - timezone.now()).total_seconds())), flujo.get("reenvios_simulados", 0)


@login_not_required
def validar_codigo(request):
    flujo = _flujo(request)
    if not flujo:
        messages.warning(request, "Primero solicite un código de recuperación.")
        return redirect("cuentas:recuperar")
    solicitud = _solicitud(flujo)
    form = ValidarCodigoForm(request.POST if request.method == "POST" else None)
    max_intentos = settings.RECUPERACION_MAX_INTENTOS
    if request.method == "POST" and form.is_valid():
        codigo = form.cleaned_data["codigo"]
        if solicitud is None:
            flujo["intentos_simulados"] = flujo.get("intentos_simulados", 0) + 1
            request.session.modified = True
            if flujo["intentos_simulados"] >= max_intentos:
                form.add_error("codigo", "Superó el máximo de intentos. Solicite un nuevo código.")
            else:
                form.add_error("codigo", f"Código incorrecto. Le quedan "
                                         f"{max_intentos - flujo['intentos_simulados']} intento(s).")
        elif not solicitud.utilizable:
            form.add_error("codigo", "Este código ya fue utilizado o fue reemplazado por uno nuevo. "
                                     "Solicite un nuevo código.")
        elif solicitud.bloqueada:
            form.add_error("codigo", "Superó el máximo de intentos. Solicite un nuevo código.")
        elif solicitud.vencida:
            form.add_error("codigo", "El código venció. Use «Reenviar código» para recibir uno nuevo.")
        elif not solicitud.codigo_correcto(codigo):
            solicitud.intentos += 1
            solicitud.save(update_fields=["intentos"])
            if solicitud.bloqueada:
                form.add_error("codigo", "Código incorrecto. Superó el máximo de intentos: solicite un nuevo código.")
            else:
                form.add_error("codigo", f"Código incorrecto. Le quedan {max_intentos - solicitud.intentos} intento(s).")
        else:
            solicitud.verificado_en = timezone.now()
            solicitud.save(update_fields=["verificado_en"])
            flujo["verificado"] = True
            request.session.modified = True
            messages.success(request, "Código verificado. Ahora cree su nueva contraseña.")
            return redirect("cuentas:nueva_clave")
    expira, espera, reenvios = _estado_tiempos(flujo, solicitud)
    return render(request, "auth/validar_codigo.html", {
        "form": form,
        "correo": flujo["correo"],
        "expira_iso": expira.isoformat(),
        "segundos_reenvio": espera,
        "reenvios_restantes": max(0, settings.RECUPERACION_MAX_REENVIOS - reenvios),
        "vigencia": settings.RECUPERACION_VIGENCIA_MINUTOS,
        "errores_formulario": request.method == "POST" and bool(form.errors),
    })


@login_not_required
@require_POST
def reenviar_codigo(request):
    flujo = _flujo(request)
    if not flujo:
        return redirect("cuentas:recuperar")
    solicitud = _solicitud(flujo)
    _, espera, reenvios = _estado_tiempos(flujo, solicitud)
    if espera > 0:
        messages.warning(request, f"Espere {espera} segundos antes de solicitar un nuevo código.")
    elif reenvios >= settings.RECUPERACION_MAX_REENVIOS:
        messages.error(request, "Alcanzó el máximo de reenvíos. Inicie nuevamente la recuperación.")
    elif solicitud is None:
        flujo["envio_simulado"] = timezone.now().isoformat()
        flujo["reenvios_simulados"] = reenvios + 1
        flujo["intentos_simulados"] = 0
        request.session.modified = True
        messages.info(request, MENSAJE_GENERICO)
    elif not solicitud.utilizable:
        messages.error(request, "La solicitud ya no es válida. Inicie nuevamente la recuperación.")
    else:
        codigo = solicitud.renovar_codigo()
        _enviar_codigo(solicitud.usuario, codigo)
        messages.info(request, "Enviamos un nuevo código. El código anterior dejó de ser válido.")
    return redirect("cuentas:validar_codigo")


@login_not_required
def nueva_clave(request):
    flujo = _flujo(request)
    solicitud = _solicitud(flujo)
    vigente = (
        flujo and flujo.get("verificado") and solicitud and solicitud.utilizable and solicitud.verificado_en
        and timezone.now() < solicitud.verificado_en + timedelta(minutes=settings.RECUPERACION_VIGENCIA_MINUTOS)
    )
    if not vigente:
        messages.error(request, "Debe validar un código vigente antes de crear una nueva contraseña.")
        return redirect("cuentas:validar_codigo" if flujo else "cuentas:recuperar")
    usuario = solicitud.usuario
    form = NuevaClaveForm(request.POST if request.method == "POST" else None, usuario=usuario)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            usuario.set_password(form.cleaned_data["clave1"])
            usuario.debe_cambiar_clave = False  # <--- DESACTIVA LA OBLIGATORIEDAD TRAS EL CAMBIO
            usuario.save(update_fields=["password", "debe_cambiar_clave"])
            solicitud.usado_en = timezone.now()
            solicitud.save(update_fields=["usado_en"])
            usuario.solicitudes_recuperacion.filter(usado_en__isnull=True).update(anulado=True)
        cache.delete(_clave_intentos(usuario.username))
        cache.delete(_clave_intentos(usuario.correo))
        request.session.pop(SESION_RECUPERACION, None)
        messages.success(request, "Contraseña actualizada correctamente. Ingrese con su nueva contraseña.")
        return redirect("cuentas:login")
    return render(request, "auth/nueva_clave.html", {
        "form": form, "requisitos": REQUISITOS_CLAVE,
        "errores_formulario": request.method == "POST" and bool(form.errors),
    })


# =============================================================================
# Mantenedor de Roles
# =============================================================================
def _alcance_rol(rol):
    return rol.get_alcance_display()


def _resumen_permisos(rol):
    if rol.es_sistema:
        return "Todos los permisos"
    modulos = sorted({p.split(".")[0] for p in rol.permisos or []} - {"inicio"})
    return ", ".join(NOMBRE_MODULO.get(m, m) for m in modulos) or "Solo inicio"


class RolesMantenedor(Mantenedor):
    modulo = "roles"
    model = Rol
    form_class = RolForm
    titulo = "Roles y permisos"
    singular = "rol"
    plantilla_form = "cuentas/rol_form.html"
    plantilla_detalle = "cuentas/rol_detalle.html"
    campos_busqueda = ["codigo", "nombre", "descripcion", "alcance"]
    columnas = [
        Columna("Código", "codigo", "enlace"),
        Columna("Rol", "nombre"),
        Columna("Alcance", _alcance_rol),
        Columna("Usuarios", lambda r: r.usuarios.count()),
        Columna("Estado", "estado_texto", "estado"),
    ]
    columnas_excel = [("Código", "codigo"), ("Rol", "nombre"), ("Descripción", "descripcion"),
                      ("Alcance", _alcance_rol), ("Módulos autorizados", _resumen_permisos),
                      ("Permisos", lambda r: ", ".join(r.permisos or [])),
                      ("Usuarios", lambda r: r.usuarios.count()), ("Estado", "estado_texto")]
    detalle = [("Código", "codigo"), ("Nombre", "nombre"), ("Descripción", "descripcion"),
               ("Alcance", _alcance_rol), ("Usuarios asignados", lambda r: r.usuarios.count())]
    filtros = [
        Filtro("alcance", "Alcance", lambda r: Rol.ALCANCES, lambda qs, v: qs.filter(alcance=v)),
        filtro_estado(),
    ]
    placeholder_busqueda = "Buscar por código, nombre o descripción…"

    def contexto_extra(self, request, obj=None):
        ctx = {"acciones": ACCIONES}
        if obj is not None:
            ctx["matriz"] = RolForm(instance=obj, request=request).matriz()
        return ctx

    def motivo_no_eliminar(self, request, obj):
        if obj.es_sistema:
            return "El rol Superadministrador es un rol protegido del sistema y no puede eliminarse."
        n = obj.usuarios.count()
        if n:
            return f"No se puede eliminar «{obj}»: tiene {n} usuario(s) asignado(s). Reasígnelos o desactive el rol."
        return None

    def motivo_no_cambiar_estado(self, request, obj):
        if obj.es_sistema:
            return "El rol Superadministrador es un rol protegido y no puede desactivarse."
        activos = obj.usuarios.filter(is_active=True).count()
        if obj.activo and activos:
            return f"No se puede desactivar «{obj}»: tiene {activos} usuario(s) activo(s). Reasígnelos primero."
        return None

    def vista_editar(self, request, pk):
        obj = self.obtener(request, pk)
        if not request.user.rol.es_sistema and (obj.es_sistema or obj.es_global):
            messages.error(request, "Solo el Superadministrador puede modificar este rol.")
            return redirect(self.url("detalle", obj.pk))
        return self._formulario(request, obj)


# =============================================================================
# Mantenedor de Usuarios
# =============================================================================
def _delegaciones_usuario(u):
    if u.rol.es_global:
        return "Todas (alcance global)"
    return ", ".join(d.codigo for d in u.delegaciones.all()) or "—"


def _opciones_ambito(request):
    if request.user.rol.es_global:
        return [("activa", "Delegación activa"), ("todas", "Todas las delegaciones")]
    return []


def _opciones_rol(request):
    return [(r.pk, r.nombre) for r in Rol.objects.all()]


class UsuariosMantenedor(Mantenedor):
    modulo = "usuarios"
    model = Usuario
    form_class = UsuarioForm
    titulo = "Usuarios"
    singular = "usuario"
    campo_estado = "is_active"
    plantilla_form = "cuentas/usuario_form.html"
    campos_busqueda = ["nombre", "username", "correo", "rol__nombre", "delegaciones__codigo",
                       "delegaciones__nombre"]
    columnas = [
        Columna("Nombre", "nombre", "enlace"),
        Columna("Usuario", "username"),
        Columna("Correo", "correo"),
        Columna("Rol", "rol.nombre"),
        Columna("Delegación", _delegaciones_usuario),
        Columna("Estado", "estado_texto", "estado"),
    ]
    columnas_excel = [("Nombre", "nombre"), ("Usuario", "username"), ("Correo", "correo"),
                      ("Rol", "rol.nombre"), ("Delegaciones autorizadas", _delegaciones_usuario),
                      ("Estado", "estado_texto"), ("Último ingreso", lambda u: u.last_login or "")]
    detalle = [("Nombre", "nombre"), ("Usuario", "username"), ("Correo", "correo"), ("Rol", "rol"),
               ("Alcance del rol", lambda u: u.rol.get_alcance_display()),
               ("Delegaciones autorizadas", _delegaciones_usuario),
               ("Último ingreso", lambda u: u.last_login or "Nunca"),
               ("Atenciones registradas", lambda u: u.atenciones.count())]
    filtros = [
        Filtro("ambito", "Ámbito", _opciones_ambito, lambda qs, v: qs),
        Filtro("rol", "Rol", _opciones_rol, lambda qs, v: qs.filter(rol_id=v)),
        filtro_estado("is_active"),
    ]
    placeholder_busqueda = "Buscar por nombre, usuario, correo, rol o delegación…"
    ayuda_lista = "Se listan los usuarios de la delegación activa según el alcance de su perfil."

    def queryset(self, request):
        qs = Usuario.objects.select_related("rol").prefetch_related("delegaciones")
        if request.user.rol.es_global:
            return qs
        return qs.filter(delegaciones=request.delegacion_activa).exclude(rol__alcance="GLOBAL")

    def filtrar(self, request):
        qs, q, valores = super().filtrar(request)
        if request.user.rol.es_global and valores.get("ambito") != "todas":
            qs = qs.filter(delegaciones=request.delegacion_activa)
        return qs, q, valores

    def motivo_no_eliminar(self, request, obj):
        if obj.pk == request.user.pk:
            return "No puede eliminar su propia cuenta."
        n = obj.atenciones.count()
        if n:
            return f"No se puede eliminar «{obj}»: es responsable de {n} atención(es). Puede desactivarlo."
        return None

    def motivo_no_cambiar_estado(self, request, obj):
        if obj.pk == request.user.pk:
            return "No puede desactivar su propia cuenta."
        return None

    def despues_de_guardar(self, request, obj, creado):
        """Si es un usuario nuevo, envía el correo con la clave provisoria."""
        if creado and hasattr(obj, "_clave_provisoria_temp") and obj._clave_provisoria_temp:
            try:
                send_mail(
                    "SGR La Serena · Bienvenida y Clave Provisoria",
                    f"Hola {obj.nombre}:\n\n"
                    f"Se ha creado su cuenta en el Sistema de Gestión de Requerimientos (SGR).\n\n"
                    f"Sus credenciales de acceso son:\n"
                    f" - Usuario: {obj.username}\n"
                    f" - Contraseña provisoria: {obj._clave_provisoria_temp}\n\n"
                    f"Al ingresar por primera vez, el sistema le solicitará cambiar esta contraseña por una definitiva.\n\n"
                    f"Atentamente,\nIlustre Municipalidad de La Serena",
                    None, [obj.correo],
                )
                messages.info(request, f"Se envió la contraseña provisoria al correo {obj.correo}.")
            except Exception:
                log.exception("Error al enviar correo de clave provisoria a %s", obj.correo)
                messages.warning(
                    request,
                    f"Usuario creado, pero no se pudo enviar el correo a {obj.correo}. Clave provisoria: {obj._clave_provisoria_temp}"
                )


roles = RolesMantenedor()
usuarios = UsuariosMantenedor()