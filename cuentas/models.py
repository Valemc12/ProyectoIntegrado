import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.utils import timezone

from catalogos.models import Delegacion
from core.permisos import TODOS_LOS_PERMISOS
from core.validadores import validar_codigo


class Rol(models.Model):
    ALCANCES = [
        ("GLOBAL", "Global (todas las delegaciones)"),
        ("MULTIPLE", "Varias delegaciones autorizadas"),
        ("DELEGACION", "Una delegación"),
    ]

    codigo = models.CharField("Código", max_length=15, unique=True, validators=[validar_codigo])
    nombre = models.CharField("Nombre", max_length=60, unique=True)
    descripcion = models.TextField("Descripción", max_length=300, blank=True)
    permisos = models.JSONField("Permisos", default=list, blank=True)
    alcance = models.CharField("Alcance", max_length=12, choices=ALCANCES, default="DELEGACION")
    activo = models.BooleanField("Estado", default=True)
    es_sistema = models.BooleanField(
        default=False, editable=False,
        help_text="Rol protegido: no se elimina ni desactiva y conserva todos los permisos.",
    )
    creado = models.DateTimeField(auto_now_add=True)
    actualizado = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["codigo"]
        verbose_name = "rol"
        verbose_name_plural = "roles"

    def __str__(self):
        return self.nombre

    def save(self, *args, **kwargs):
        self.codigo = (self.codigo or "").strip().upper()
        super().save(*args, **kwargs)

    @property
    def estado_texto(self):
        return "Activo" if self.activo else "Inactivo"

    @property
    def es_global(self):
        return self.alcance == "GLOBAL"


class UsuarioManager(BaseUserManager):
    use_in_migrations = True

    def get_by_natural_key(self, username):
        return self.get(username__iexact=username)

    def create_user(self, username, correo, password=None, **extra):
        usuario = self.model(username=username, correo=self.normalize_email(correo).lower(), **extra)
        usuario.set_password(password)
        usuario.save(using=self._db)
        return usuario


class Usuario(AbstractBaseUser):
    username = models.CharField("Usuario", max_length=30, unique=True)
    correo = models.EmailField("Correo", max_length=120, unique=True)
    nombre = models.CharField("Nombre completo", max_length=100)
    rol = models.ForeignKey(Rol, on_delete=models.PROTECT, related_name="usuarios", verbose_name="Rol")
    delegaciones = models.ManyToManyField(
        Delegacion, blank=True, related_name="usuarios", verbose_name="Delegaciones autorizadas"
    )
    # NUEVO CAMPO: Indica si el usuario debe cambiar su clave provisoria al primer ingreso
    debe_cambiar_clave = models.BooleanField("Debe cambiar clave", default=True)
    
    is_active = models.BooleanField("Estado", default=True)
    creado = models.DateTimeField(auto_now_add=True)
    actualizado = models.DateTimeField(auto_now=True)

    objects = UsuarioManager()

    USERNAME_FIELD = "username"
    EMAIL_FIELD = "correo"
    REQUIRED_FIELDS = ["correo", "nombre"]

    class Meta:
        ordering = ["nombre"]
        verbose_name = "usuario"
        verbose_name_plural = "usuarios"

    def __str__(self):
        return self.nombre

    def save(self, *args, **kwargs):
        # Usuario y correo se guardan en minúsculas: la unicidad no distingue mayúsculas.
        self.username = (self.username or "").strip().lower()
        self.correo = (self.correo or "").strip().lower()
        super().save(*args, **kwargs)

    @property
    def estado_texto(self):
        return "Activo" if self.is_active else "Inactivo"

    # --- Permisos ---------------------------------------------------------
    def tiene_permiso(self, codigo):
        if not self.is_active or not self.rol_id or not self.rol.activo:
            return False
        if self.rol.es_sistema:
            return codigo in TODOS_LOS_PERMISOS
        return codigo in (self.rol.permisos or [])

    # --- Delegaciones -----------------------------------------------------
    def delegaciones_autorizadas(self):
        """Delegaciones activas que el usuario puede usar como contexto."""
        if self.rol.es_global:
            return Delegacion.objects.filter(activo=True)
        return self.delegaciones.filter(activo=True)


class SolicitudRecuperacion(models.Model):
    """Código de 6 dígitos enviado por correo para restablecer la contraseña."""

    token = models.CharField(max_length=64, unique=True, editable=False)
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name="solicitudes_recuperacion")
    codigo_hash = models.CharField(max_length=128)
    creado = models.DateTimeField(default=timezone.now)
    expira = models.DateTimeField()
    ultimo_envio = models.DateTimeField(default=timezone.now)
    intentos = models.PositiveSmallIntegerField(default=0)
    reenvios = models.PositiveSmallIntegerField(default=0)
    verificado_en = models.DateTimeField(null=True, blank=True)
    usado_en = models.DateTimeField(null=True, blank=True)
    anulado = models.BooleanField(default=False)

    class Meta:
        ordering = ["-creado"]

    @staticmethod
    def generar_codigo():
        return f"{secrets.randbelow(1_000_000):06d}"

    @classmethod
    def crear(cls, usuario):
        codigo = cls.generar_codigo()
        ahora = timezone.now()
        solicitud = cls.objects.create(
            token=secrets.token_urlsafe(32),
            usuario=usuario,
            codigo_hash=make_password(codigo),
            creado=ahora,
            ultimo_envio=ahora,
            expira=ahora + timedelta(minutes=settings.RECUPERACION_VIGENCIA_MINUTOS),
        )
        return solicitud, codigo

    def renovar_codigo(self):
        codigo = self.generar_codigo()
        ahora = timezone.now()
        self.codigo_hash = make_password(codigo)
        self.ultimo_envio = ahora
        self.expira = ahora + timedelta(minutes=settings.RECUPERACION_VIGENCIA_MINUTOS)
        self.intentos = 0
        self.reenvios += 1
        self.save()
        return codigo

    def codigo_correcto(self, codigo):
        return check_password(codigo, self.codigo_hash)

    @property
    def vencida(self):
        return timezone.now() >= self.expira

    @property
    def bloqueada(self):
        return self.intentos >= settings.RECUPERACION_MAX_INTENTOS

    @property
    def utilizable(self):
        return not (self.anulado or self.usado_en)

    def segundos_para_reenvio(self):
        espera = self.ultimo_envio + timedelta(seconds=settings.RECUPERACION_ESPERA_REENVIO_SEG)
        return max(0, int((espera - timezone.now()).total_seconds()))