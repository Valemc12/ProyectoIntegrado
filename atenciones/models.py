from django.conf import settings
from django.db import models

from catalogos.models import Delegacion, SubAtencion, TipoAtencion
from core.validadores import formatear_rut, normalizar_rut, validar_rut


class Vecino(models.Model):
    """Solicitante de la atención."""

    rut = models.CharField("RUT", max_length=12, unique=True, validators=[validar_rut])
    nombre = models.CharField("Nombre completo", max_length=100)
    telefono = models.CharField("Teléfono", max_length=20, blank=True)
    correo = models.EmailField("Correo", max_length=120, blank=True)
    direccion = models.CharField("Dirección", max_length=150, blank=True)
    # NUEVO CAMPO: Comuna por defecto "La Serena"
    comuna = models.CharField("Comuna", max_length=60, default="La Serena", blank=True)
    creado = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["nombre"]
        verbose_name = "vecino"

    def save(self, *args, **kwargs):
        self.rut = normalizar_rut(self.rut)
        if not self.comuna:
            self.comuna = "La Serena"
        super().save(*args, **kwargs)

    @property
    def rut_formateado(self):
        return formatear_rut(self.rut)

    def __str__(self):
        return f"{self.rut_formateado} · {self.nombre}"


class Atencion(models.Model):
    vecino = models.ForeignKey(Vecino, on_delete=models.PROTECT, related_name="atenciones",
                               verbose_name="Vecino o solicitante")
    tipo = models.ForeignKey(TipoAtencion, on_delete=models.PROTECT, related_name="atenciones",
                             verbose_name="Tipo de Atención")
    subatencion = models.ForeignKey(SubAtencion, on_delete=models.PROTECT, related_name="atenciones",
                                    verbose_name="Sub Atención")
    descripcion = models.TextField("Descripción de la atención", max_length=1000)
    delegacion = models.ForeignKey(Delegacion, on_delete=models.PROTECT, related_name="atenciones",
                                   verbose_name="Delegación")
    responsable = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
                                    related_name="atenciones", verbose_name="Usuario responsable")
    fecha_registro = models.DateTimeField("Fecha de registro", auto_now_add=True)
    token_envio = models.CharField(max_length=64, unique=True, null=True, blank=True, editable=False)

    class Meta:
        ordering = ["-fecha_registro"]
        verbose_name = "atención"
        verbose_name_plural = "atenciones"

    @property
    def folio(self):
        anio = self.fecha_registro.year if self.fecha_registro else ""
        return f"AT-{anio}-{self.pk:06d}"

    def __str__(self):
        return self.folio