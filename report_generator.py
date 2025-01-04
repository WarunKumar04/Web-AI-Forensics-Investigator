from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_report(output_file='output/attack_report.pdf'):
    c = canvas.Canvas(output_file, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, height - 50, "Attack Detection Report")

    
    detected_attacks = [
        {"log": "GET /images.php?file=../../etc/passwd", "label": "Path Traversal"},
        {"log": "POST /command.php HTTP/1.1", "label": "Command Injection"},
        {"log": "GET /view.php?image=../../../etc/passwd", "label": "Path Traversal"}
    ]

    y_position = height - 100
    c.setFont("Helvetica", 12)

    for attack in detected_attacks:
        c.drawString(100, y_position, f"Log: {attack['log']}")
        c.drawString(100, y_position - 15, f"Attack Type: {attack['label']}")
        y_position -= 40

    c.save()

if __name__ == "__main__":
    generate_report()
