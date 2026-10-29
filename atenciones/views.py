import logging
import secrets

from django import forms
from django.contrib import messages
from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import path

from catalogos.models import SubAtencion, TipoAtencion
from core.crud import Columna, Filtro, Mantenedor
from core.permisos import requiere_permiso
from core.validadores import normalizar_rut, validar_rut

from .models import Atencion, Vecino

log = logging.getLogger("sgr")
SESION_TOKENS = "tokens_atencion"


class AtencionForm(forms.Form):
    MODOS = [("existente", "Vecino registrado"), ("nuevo", "Registrar nuevo vecino")]

    modo_vecino = forms.ChoiceField(choices=MODOS, initial="existente", widget=forms.RadioSelect)
    vecino = forms.ModelChoiceField(queryset=Vecino.objects.all(), required=False,
                                    widget=forms.HiddenInput, label="Vecino o solicitante")
    rut = forms.CharField(label="RUT", required=False, max_length=12)
    nombre = forms.CharField(label="Nombre completo", required=False, max_length=100)
    telefono = forms.CharField(label="Teléfono", required=False, max_length=20)
    correo = forms.EmailField(label="Correo", required=False, max_length=120)
    # NUEVO CAMPO FORMULARIO: Comuna con valor por defecto "La Serena"
    comuna = forms.CharField(label="Comuna", required=False, max_length=60, initial="La Serena")
    
    tipo = forms.ModelChoiceField(label="Tipo de Atención", queryset=TipoAtencion.objects.filter(activo=True),
                                  empty_label="Seleccione un tipo…",
                                  error_messages={"required": "Seleccione el Tipo de Atención.",
                                                  "invalid_choice": "El Tipo de Atención no es válido o está inactivo."})
    subatencion = forms.ModelChoiceField(label="Sub Atención", queryset=SubAtencion.objects.filter(activo=True),
                                         empty_label="Seleccione primero un tipo…",
                                         error_messages={"required": "Seleccione la Sub Atención.",
                                                         "invalid_choice": "La Sub Atención no es válida o está inactiva."})
    descripcion = forms.CharField(label="Descripción de la atención", max_length=1000, min_length=10,
                                  widget=forms.Textarea(attrs={"rows": 4}),
                                  error_messages={"required": "Describa la solicitud.",
                                                  "min_length": "Describa la solicitud con al menos 10 caracteres."})
    token = forms.CharField(widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for nombre, campo in self.fields.items():
            if isinstance(campo.widget, (forms.HiddenInput, forms.RadioSelect)):
                continue
            campo.widget.attrs["class"] = "campo-select" if isinstance(campo.widget, forms.Select) else "campo-input"
            max_length = getattr(campo, "max_length", None)
            if max_length:
                campo.widget.attrs["maxlength"] = max_length
        for nombre in ("tipo", "subatencion", "descripcion"):
            self.fields[nombre].widget.attrs["required"] = True
        self.fields["rut"].widget.attrs["placeholder"] = "12.345.678-9"
        self.fields["comuna"].widget.attrs["placeholder"] = "La Serena"
        self.fields["descripcion"].widget.attrs["placeholder"] = "Describa la solicitud y los antecedentes necesarios."
        tipo_id = self.data.get("tipo") if self.is_bound else None
        if tipo_id and str(tipo_id).isdigit():
            self.fields["subatencion"].queryset = SubAtencion.objects.filter(activo=True, tipo_id=tipo_id,
                                                                             tipo__activo=True)
        elif self.is_bound:
            self.fields["subatencion"].queryset = SubAtencion.objects.none()

    def clean(self):
        datos = super().clean()
        if datos.get("modo_vecino") == "nuevo":
            rut = datos.get("rut", "")
            if not rut:
                self.add_error("rut", "Ingrese el RUT del vecino.")
            else:
                try:
                    validar_rut(rut)
                except forms.ValidationError as e:
                    self.add_error("rut", e)
                else:
                    if Vecino.objects.filter(rut=normalizar_rut(rut)).exists():
                        self.add_error("rut", "Este RUT ya está registrado. Búsquelo como vecino registrado.")
            nombre = " ".join((datos.get("nombre") or "").split())
            if len(nombre) < 3:
                self.add_error("nombre", "Ingrese el nombre del vecino (mínimo 3 caracteres).")
            datos["nombre"] = nombre
            if not datos.get("comuna"):
                datos["comuna"] = "La Serena"
        elif not datos.get("vecino"):
            self.add_error("vecino", "Busque y seleccione al vecino o solicitante.")
        tipo, sub = datos.get("tipo"), datos.get("subatencion")
        if tipo and sub and sub.tipo_id != tipo.pk:
            self.add_error("subatencion", "La Sub Atención no corresponde al Tipo de Atención seleccionado.")
        return datos


def _nuevo_token(request):
    token = secrets.token_urlsafe(24)
    tokens = request.session.get(SESION_TOKENS, [])[-9:]
    tokens.append(token)
    request.session[SESION_TOKENS] = tokens
    return token


@requiere_permiso("atenciones.ver", "atenciones.crear")
def crear_atencion(request):
    if request.method == "POST":
        form = AtencionForm(request.POST)
        token = request.POST.get("token", "")
        previa = Atencion.objects.filter(token_envio=token).first() if token else None
        if previa:
            messages.warning(request, f"Esta atención ya fue registrada con el folio {previa.folio}.")
            return redirect("atenciones:detalle", previa.pk)
        if token not in request.session.get(SESION_TOKENS, []):
            messages.error(request, "El formulario expiró. Revise los datos y vuelva a guardar.")
            form.data = form.data.copy()
            form.data["token"] = _nuevo_token(request)
        elif form.is_valid():
            datos = form.cleaned_data
            try:
                with transaction.atomic():
                    vecino = datos["vecino"]
                    if datos["modo_vecino"] == "nuevo":
                        vecino = Vecino.objects.create(
                            rut=normalizar_rut(datos["rut"]),
                            nombre=datos["nombre"],
                            telefono=datos.get("telefono", ""),
                            correo=datos.get("correo", ""),
                            comuna=datos.get("comuna", "La Serena") or "La Serena"
                        )
                    atencion = Atencion.objects.create(
                        vecino=vecino, tipo=datos["tipo"], subatencion=datos["subatencion"],
                        descripcion=datos["descripcion"].strip(),
                        delegacion=request.delegacion_activa,
                        responsable=request.user,
                        token_envio=token,
                    )
            except IntegrityError:
                previa = Atencion.objects.filter(token_envio=token).first()
                if previa:
                    messages.warning(request, f"Esta atención ya fue registrada con el folio {previa.folio}.")
                    return redirect("atenciones:detalle", previa.pk)
                log.exception("Error de integridad al registrar atención")
                messages.error(request, "No fue posible registrar la atención. No se guardaron cambios.")
            except DatabaseError:
                log.exception("Error al registrar atención")
                messages.error(request, "No fue posible registrar la atención por un error del servidor. "
                                        "No se guardaron cambios.")
            else:
                request.session[SESION_TOKENS] = [t for t in request.session.get(SESION_TOKENS, []) if t != token]
                request.session["atencion_creada"] = atencion.folio
                messages.success(request, f"Atención registrada correctamente. Folio: {atencion.folio}")
                return redirect("atenciones:detalle", atencion.pk)
    else:
        form = AtencionForm(initial={"token": _nuevo_token(request), "modo_vecino": "existente", "comuna": "La Serena"})
    vecino_sel = None
    if form.is_bound and form.data.get("vecino", "").isdigit():
        vecino_sel = Vecino.objects.filter(pk=form.data["vecino"]).first()
    return render(request, "atenciones/form.html", {
        "form": form, "vecino_sel": vecino_sel,
        "errores_formulario": request.method == "POST" and bool(form.errors),
    })


@requiere_permiso("atenciones.crear")
def api_subatenciones(request):
    tipo = request.GET.get("tipo", "")
    if not tipo.isdigit():
        return JsonResponse({"resultados": []})
    subs = SubAtencion.objects.filter(tipo_id=tipo, activo=True, tipo__activo=True).order_by("nombre")
    return JsonResponse({"resultados": [{"id": s.pk, "texto": s.nombre} for s in subs]})


@requiere_permiso("atenciones.crear")
def api_vecinos(request):
    q = " ".join(request.GET.get("q", "").split())[:60]
    if len(q) < 2:
        return JsonResponse({"resultados": []})
    filtro = Q(nombre__icontains=q)
    rut = normalizar_rut(q)
    if len(rut) >= 3 and rut[:-1].isdigit():
        filtro |= Q(rut__startswith=rut) | Q(rut__startswith=rut.rstrip("K"))
    vecinos = Vecino.objects.filter(filtro).order_by("nombre")[:8]
    return JsonResponse({"resultados": [{"id": v.pk, "texto": str(v)} for v in vecinos]})


# --- Listado y consulta de atenciones (alcance: delegación activa) ------------
def _opciones_tipos(request):
    return [(t.pk, t.nombre) for t in TipoAtencion.objects.all()]


class AtencionesMantenedor(Mantenedor):
    modulo = "atenciones"
    model = Atencion
    titulo = "Atenciones"
    singular = "atención"
    femenino = True
    campo_estado = None
    plantilla_detalle = "atenciones/detalle.html"
    campos_busqueda = ["vecino__nombre", "vecino__rut", "descripcion", "tipo__nombre", "subatencion__nombre",
                       "responsable__nombre"]
    columnas = [
        Columna("Folio", "folio", "enlace"),
        Columna("Fecha", lambda a: a.fecha_registro),
        Columna("Vecino", "vecino.nombre"),
        Columna("Tipo", "tipo.nombre"),
        Columna("Sub Atención", "subatencion.nombre"),
        Columna("Responsable", "responsable.nombre"),
    ]
    columnas_excel = [("Folio", "folio"), ("Fecha de registro", "fecha_registro"),
                      ("RUT vecino", "vecino.rut_formateado"), ("Vecino", "vecino.nombre"),
                      ("Tipo de Atención", "tipo.nombre"), ("Sub Atención", "subatencion.nombre"),
                      ("Descripción", "descripcion"), ("Delegación", "delegacion"),
                      ("Responsable", "responsable.nombre")]
    detalle = [("Folio", "folio"), ("Fecha y hora de registro", "fecha_registro"),
               ("Vecino o solicitante", "vecino"), ("Teléfono", "vecino.telefono"), ("Correo", "vecino.correo"),
               ("Comuna", "vecino.comuna"),
               ("Tipo de Atención", "tipo"), ("Sub Atención", "subatencion"), ("Descripción", "descripcion"),
               ("Delegación", "delegacion"), ("Usuario responsable", "responsable")]
    filtros = [Filtro("tipo", "Tipo", _opciones_tipos, lambda qs, v: qs.filter(tipo_id=v))]
    placeholder_busqueda = "Buscar por vecino, RUT, tipo, descripción o responsable…"

    def queryset(self, request):
        qs = Atencion.objects.select_related("vecino", "tipo", "subatencion", "delegacion", "responsable")
        return qs.filter(delegacion=request.delegacion_activa)

    def contexto_base(self, request, **extra):
        ctx = super().contexto_base(request, **extra)
        ctx["nuevo_texto"] = "Ingresar atención"
        return ctx

    def urls(self):
        ver = requiere_permiso("atenciones.ver")
        patrones = [
            path("", ver(self.vista_lista), name="lista"),
            path("nueva/", crear_atencion, name="crear"),
            path("exportar/", requiere_permiso("atenciones.ver", "atenciones.exportar")(self.vista_exportar),
                 name="exportar"),
            path("<int:pk>/", ver(self.vista_detalle), name="detalle"),
            path("api/subatenciones/", api_subatenciones, name="api_subatenciones"),
            path("api/vecinos/", api_vecinos, name="api_vecinos"),
        ]
        return patrones, "atenciones"


atenciones = AtencionesMantenedor()