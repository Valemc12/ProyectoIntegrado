import re
import secrets

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from catalogos.models import Delegacion
from core.crud import FormularioBase
from core.permisos import MODULOS, TODOS_LOS_PERMISOS

from .models import Rol, Usuario


# --- Acceso y recuperación ---------------------------------------------------
class LoginForm(forms.Form):
    identificador = forms.CharField(
        label="Usuario o correo", max_length=120,
        error_messages={"required": "Ingrese su usuario o correo."},
        widget=forms.TextInput(attrs={"class": "campo-input", "autocomplete": "username", "autofocus": True,
                                      "placeholder": "usuario o nombre@laserena.cl"}),
    )
    clave = forms.CharField(
        label="Contraseña", max_length=128, strip=False,
        error_messages={"required": "Ingrese su contraseña."},
        widget=forms.PasswordInput(attrs={"class": "campo-input", "autocomplete": "current-password",
                                          "placeholder": "Su contraseña"}),
    )


class SolicitarCodigoForm(forms.Form):
    correo = forms.EmailField(
        label="Correo asociado a la cuenta", max_length=120,
        error_messages={"required": "Ingrese el correo asociado a su cuenta.",
                        "invalid": "Ingrese un correo válido (ej.: nombre@laserena.cl)."},
        widget=forms.EmailInput(attrs={"class": "campo-input", "autocomplete": "email", "autofocus": True,
                                       "placeholder": "nombre@laserena.cl"}),
    )


class ValidarCodigoForm(forms.Form):
    codigo = forms.CharField(
        label="Código de verificación", min_length=6, max_length=6,
        error_messages={"required": "Ingrese el código de 6 dígitos.",
                        "min_length": "El código debe tener 6 dígitos."},
    )

    def clean_codigo(self):
        codigo = re.sub(r"\s", "", self.cleaned_data["codigo"])
        if not re.fullmatch(r"\d{6}", codigo):
            raise ValidationError("El código debe tener exactamente 6 dígitos numéricos.")
        return codigo


class NuevaClaveForm(forms.Form):
    clave1 = forms.CharField(
        label="Nueva contraseña", strip=False, max_length=64,
        error_messages={"required": "Ingrese la nueva contraseña."},
        widget=forms.PasswordInput(attrs={"class": "campo-input", "autocomplete": "new-password", "autofocus": True}),
    )
    clave2 = forms.CharField(
        label="Confirmar contraseña", strip=False, max_length=64,
        error_messages={"required": "Confirme la nueva contraseña."},
        widget=forms.PasswordInput(attrs={"class": "campo-input", "autocomplete": "new-password"}),
    )

    def __init__(self, *args, usuario=None, **kwargs):
        self.usuario = usuario
        super().__init__(*args, **kwargs)

    def clean(self):
        datos = super().clean()
        c1, c2 = datos.get("clave1"), datos.get("clave2")
        if c1:
            try:
                validate_password(c1, self.usuario)
            except ValidationError as e:
                self.add_error("clave1", e)
            if self.usuario and self.usuario.check_password(c1):
                self.add_error("clave1", "La nueva contraseña debe ser distinta de la anterior.")
        if c1 and c2 and c1 != c2:
            self.add_error("clave2", "Las contraseñas no coinciden.")
        return datos


# --- Roles -------------------------------------------------------------------
class RolForm(FormularioBase):
    permisos = forms.MultipleChoiceField(
        label="Permisos", required=False, choices=[(p, p) for p in TODOS_LOS_PERMISOS],
        widget=forms.CheckboxSelectMultiple,
    )
    unicos = {"codigo": "Ya existe un rol con este código.", "nombre": "Ya existe un rol con este nombre."}

    class Meta:
        model = Rol
        fields = ["codigo", "nombre", "descripcion", "alcance", "activo", "permisos"]
        widgets = {"descripcion": forms.Textarea}
        labels = {"activo": "Activo"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["alcance"].help_text = "Define qué delegaciones puede usar un usuario con este rol."
        if self.instance.es_sistema:
            for nombre in ("alcance", "activo", "permisos"):
                self.fields[nombre].disabled = True

    def matriz(self):
        """Filas de la matriz de permisos para la plantilla."""
        seleccion = set(self["permisos"].value() or [])
        filas = []
        for codigo, nombre, acciones, estado in MODULOS:
            celdas = []
            for accion in ("ver", "crear", "editar", "eliminar", "exportar"):
                permiso = f"{codigo}.{accion}"
                celdas.append({"permiso": permiso, "disponible": accion in acciones,
                               "marcado": permiso in seleccion})
            filas.append({"codigo": codigo, "nombre": nombre, "estado": estado, "celdas": celdas})
        return filas

    def clean(self):
        datos = super().clean()
        if self.instance.es_sistema:
            datos["permisos"] = list(TODOS_LOS_PERMISOS)
            datos["alcance"], datos["activo"] = "GLOBAL", True
            return datos
        permisos = set(datos.get("permisos") or [])
        permisos |= {p.split(".")[0] + ".ver" for p in permisos}
        if permisos and "inicio.ver" not in permisos:
            permisos.add("inicio.ver")
        if not permisos:
            self.add_error("permisos", "Seleccione al menos un permiso.")
        editor = self.request.user if self.request else None
        if editor and not editor.rol.es_sistema:
            ajenos = sorted(p for p in permisos if not editor.tiene_permiso(p))
            if ajenos:
                self.add_error("permisos", "No puede otorgar permisos que su rol no posee: " + ", ".join(ajenos))
            if datos.get("alcance") == "GLOBAL":
                self.add_error("alcance", "Solo el Superadministrador puede crear roles de alcance global.")
        if self.instance.pk and self.instance.activo and not datos.get("activo"):
            activos = self.instance.usuarios.filter(is_active=True).count()
            if activos:
                self.add_error("activo", f"Tiene {activos} usuario(s) activo(s). Reasígnelos antes de desactivarlo.")
        datos["permisos"] = [p for p in TODOS_LOS_PERMISOS if p in permisos]
        return datos


# --- Usuarios ----------------------------------------------------------------
class UsuarioForm(FormularioBase):
    clave1 = forms.CharField(label="Contraseña", required=False, strip=False, max_length=64,
                             widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    clave2 = forms.CharField(label="Confirmar contraseña", required=False, strip=False, max_length=64,
                             widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    unicos = {"username": "Ya existe un usuario con este nombre de usuario.",
              "correo": "Ya existe un usuario con este correo."}
    minimos = {"nombre": 3, "username": 3}

    class Meta:
        model = Usuario
        fields = ["nombre", "username", "correo", "rol", "delegaciones", "is_active"]
        widgets = {"delegaciones": forms.CheckboxSelectMultiple}
        labels = {"is_active": "Activo"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        editor = self.request.user
        roles = Rol.objects.filter(activo=True)
        if not editor.rol.es_sistema:
            permitidos = [r.pk for r in roles.exclude(alcance="GLOBAL").exclude(es_sistema=True)
                          if set(r.permisos or []) <= set(editor.rol.permisos or [])]
            roles = roles.filter(pk__in=permitidos)
        if self.instance.pk and self.instance.rol_id:
            roles = roles | Rol.objects.filter(pk=self.instance.rol_id)
        self.fields["rol"].queryset = roles.distinct()
        self.fields["rol"].empty_label = "Seleccione un rol…"
        self.fields["delegaciones"].queryset = Delegacion.objects.filter(
            pk__in=[d.pk for d in self.request.delegaciones_autorizadas])
        self.fields["delegaciones"].help_text = (
            "Rol de una delegación: marque una. Varias delegaciones: marque al menos una. "
            "Alcance global: opcional.")
        self.fields["username"].widget.attrs.update({"pattern": "[A-Za-z0-9._-]{3,30}", "autocomplete": "off"})
        for nombre in ("clave1", "clave2"):
            self.fields[nombre].widget.attrs["class"] = "campo-input"
        
        if self.instance.pk:
            self.fields["clave1"].label = "Nueva contraseña (opcional)"
            self.fields["clave1"].help_text = "Déjela en blanco para mantener la contraseña actual."
        else:
            self.fields["clave1"].label = "Contraseña provisoria (Opcional)"
            self.fields["clave1"].help_text = "Si se deja en blanco, el sistema generará una provisoria automáticamente y se la enviará por correo."

        if self.instance.pk and self.instance.pk == editor.pk:
            self.fields["rol"].disabled = True
            self.fields["is_active"].disabled = True
            self.fields["rol"].help_text = "No puede cambiar su propio rol ni desactivar su propia cuenta."

    def clean_username(self):
        valor = self.cleaned_data["username"].strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,30}", valor):
            raise ValidationError("Use de 3 a 30 caracteres: letras, números, punto, guion o guion bajo.")
        return valor.lower()

    def clean_correo(self):
        return self.cleaned_data["correo"].strip().lower()

    def clean(self):
        datos = super().clean()
        rol, delegaciones = datos.get("rol"), list(datos.get("delegaciones") or [])
        if rol:
            fuera = self._delegaciones_fuera_de_alcance()
            total = len(delegaciones) + len(fuera)
            if rol.alcance == "DELEGACION" and total != 1:
                self.add_error("delegaciones", "El rol seleccionado trabaja con una sola delegación: marque exactamente una.")
            elif rol.alcance == "MULTIPLE" and total < 1:
                self.add_error("delegaciones", "Marque al menos una delegación autorizada.")
        c1, c2 = datos.get("clave1"), datos.get("clave2")
        if c1 or c2:
            if c1 != c2:
                self.add_error("clave2", "Las contraseñas no coinciden.")
            elif c1:
                try:
                    validate_password(c1, self.instance if self.instance.pk else None)
                except ValidationError as e:
                    self.add_error("clave1", e)
        return datos

    def _delegaciones_fuera_de_alcance(self):
        """Delegaciones del usuario editado que el editor no administra (se conservan)."""
        if not self.instance.pk:
            return []
        alcance = {d.pk for d in self.request.delegaciones_autorizadas}
        return [d for d in self.instance.delegaciones.all() if d.pk not in alcance]

    def save(self, commit=True):
        fuera = self._delegaciones_fuera_de_alcance()
        usuario = super().save(commit=False)
        
        clave_provisoria = self.cleaned_data.get("clave1")
        if not clave_provisoria and not usuario.pk:
            clave_provisoria = secrets.token_urlsafe(8)
            usuario.debe_cambiar_clave = True

        if clave_provisoria:
            usuario.set_password(clave_provisoria)

        usuario.save()
        usuario.delegaciones.set(list(self.cleaned_data.get("delegaciones") or []) + fuera)
        
        # Guardamos la clave generada en una propiedad temporal para usarla en el envío de correo
        usuario._clave_provisoria_temp = clave_provisoria if not self.instance.pk else None
        return usuario