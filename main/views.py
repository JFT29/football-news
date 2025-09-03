from django.shortcuts import render

# Create your views here.
def show_main(request):
    context = {
        'npm' : '2406365345',
        'name': 'Juansao Fortunio Tandi',
        'class': 'KKI'
    }

    return render(request, "main.html", context)